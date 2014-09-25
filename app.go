package main

import (
	"./sessions"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"github.com/gorilla/securecookie"
	"github.com/russross/blackfriday"
	"html"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	memosPerPage = 100
	listenAddr   = ":80"
	sessionName  = "isucon_session"
)

func must(err error) {
	if err != nil {
		log.Panic(err)
	}
}

// Split first line from given string.
func firstLine(s string) string {
	pos := strings.Index(s, "\n")
	if pos == -1 {
		return s
	} else {
		return s[:pos]
	}
}

type Config struct {
	Database struct {
		Dbname   string `json:"dbname"`
		Host     string `json:"host"`
		Port     int    `json:"port"`
		Username string `json:"username"`
		Password string `json:"password"`
	} `json:"database"`
}

type Session struct {
	Token  string
	UserId int
	Key    string
}

type SessionStore struct {
	sync.Mutex
	store map[string]*Session
}

var sessionStore = SessionStore{
	store: make(map[string]*Session),
}

func (self *SessionStore) Get(r *http.Request) *Session {
	cookie, _ := r.Cookie(sessionName)
	if cookie == nil {
		return &Session{}
	}
	key := cookie.Value
	self.Lock()
	s := self.store[key]
	self.Unlock()
	if s == nil {
		s = &Session{}
	}
	return s
}

func (self *SessionStore) Set(w http.ResponseWriter, sess *Session) {
	key := sess.Key
	if key == "" {
		b := make([]byte, 8)
		rand.Read(b)
		key = hex.EncodeToString(b)
		sess.Key = key
	}

	cookie := sessions.NewCookie(sessionName, key, &sessions.Options{})
	http.SetCookie(w, cookie)

	self.Lock()
	self.store[key] = sess
	self.Unlock()
}

type User struct {
	Id         int
	Username   string
	Password   string
	Salt       string
	LastAccess string
}

type Memo struct {
	Id        int
	User      int
	Content   string
	IsPrivate int
	CreatedAt string
	UpdatedAt string
	Username  string
	markdown  template.HTML
	firstline string
	titleLi   string
	mlock     sync.Mutex
	prevId    int
	nextId    int
}

// Convert memo.Content to HTML and return it.
func (memo *Memo) Markdown() template.HTML {
	memo.mlock.Lock()
	defer memo.mlock.Unlock()

	if memo.markdown == template.HTML("") {
		memo.markdown = template.HTML(string(blackfriday.MarkdownBasic([]byte(memo.Content))))
	}
	return memo.markdown
}

// Channel for convert markdown asynchronoushly.
var markdownConvertChan = make(chan *Memo)

// markdownConverter receives memo from markdownConvertChan
// and convert it.
func markdownConverter() {
	for memo := range markdownConvertChan {
		memo.Markdown()
	}
}

var anonymousHeader string

const footer = `</div>
<script type="text/javascript" src="/js/jquery.min.js"></script>
<script type="text/javascript" src="/js/bootstrap.min.js"></script>
</body></html>`

type View struct {
	User      *User
	Memo      *Memo
	Memos     []*Memo
	Page      int
	PageStart int
	PageEnd   int
	Total     int
	Older     *Memo
	Newer     *Memo
	Session   *Session
	BaseUrl   string
}

type PageCache struct {
	page   string
	expire int64
}

var M = struct {
	lock            sync.RWMutex
	users           map[int]*User
	memos           []*Memo
	publicMemos     []*Memo
	maxMemoId       int
	recentPageCache map[int]PageCache
}{
	lock:            sync.RWMutex{},
	users:           make(map[int]*User, 100),
	memos:           []*Memo{},
	publicMemos:     []*Memo{},
	maxMemoId:       0,
	recentPageCache: make(map[int]PageCache),
}

type MemosForUser struct {
	sync.Mutex
	memos map[int][]*Memo
}

var memosForUser = MemosForUser{
	memos: make(map[int][]*Memo),
}

func (m *MemosForUser) GetMemo(userId int) []*Memo {
	m.Lock()
	ms := m.memos[userId]
	m.Unlock()
	return ms
}

func (m *MemosForUser) AddMemo(memo *Memo) {
	m.Lock()
	ms := m.memos[memo.User]
	if len(ms) > 0 {
		prev := ms[len(ms)-1]
		prev.nextId = memo.Id
		memo.prevId = prev.Id
	}
	m.memos[memo.User] = append(ms, memo)
	m.Unlock()
}

func (m *MemosForUser) Reset() {
	m.Lock()
	m.memos = make(map[int][]*Memo)
	m.Unlock()
}

func addMemo(memo *Memo) {
	if len(M.memos) < memo.Id+1 {
		t := make([]*Memo, memo.Id*2+5)
		copy(t, M.memos)
		M.memos = t
	}
	if M.memos[memo.Id] == nil && memo.IsPrivate == 0 {
		M.publicMemos = append(M.publicMemos, memo)
	}
	M.memos[memo.Id] = memo
	if memo.Id > M.maxMemoId {
		M.maxMemoId = memo.Id
	}
	memo.firstline = html.EscapeString(firstLine(memo.Content))
	memo.titleLi = fmt.Sprintf(`<li><a href="/memo/%d">%s</a> by %s (%s)</li>`,
		memo.Id, memo.firstline, html.EscapeString(memo.Username), memo.CreatedAt)
	memosForUser.AddMemo(memo)
}

var (
	DB   *sql.DB
	fmap = template.FuncMap{
		"first_line": func(s string) string {
			sl := strings.Split(s, "\n")
			return sl[0]
		},
		"get_token": func(session *Session) interface{} {
			return session.Token
		},
	}
	tmpl = template.Must(template.New("tmpl").Funcs(fmap).ParseGlob("templates/*.html"))
)

var insertMemoStmt *sql.Stmt

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)

	v := View{}
	buf := bytes.Buffer{}
	renderTop(&buf, &v)
	anonymousHeader = buf.String()
}

func main() {
	env := os.Getenv("ISUCON_ENV")
	if env == "" {
		env = "local"
	}
	config := loadConfig("../config/" + env + ".json")
	db := config.Database
	connectionString := fmt.Sprintf(
		"%s:%s@unix(/var/lib/mysql/mysql.sock)/%s?charset=utf8&sql_mode=NO_BACKSLASH_ESCAPES",
		db.Username, db.Password, db.Dbname,
	)
	log.Printf("db: %s", connectionString)

	var err error
	DB, err = sql.Open("mysql", connectionString)
	if err != nil {
		log.Panic(err)
	}
	DB.SetMaxIdleConns(256)

	insertMemoStmt, err = DB.Prepare("INSERT INTO memos (user, content, is_private, created_at) VALUES (?, ?, ?, ?)")
	if err != nil {
		log.Panic(err)
	}
	go markdownConverter()
	go markdownConverter()

	log.Printf("Starting initial loading.")
	initialLoad()
	log.Printf("Initial loading complete.")

	r := mux.NewRouter()
	r.HandleFunc("/", topHandler)
	r.HandleFunc("/signin", signinHandler).Methods("GET", "HEAD")
	r.HandleFunc("/signin", signinPostHandler).Methods("POST")
	r.HandleFunc("/signout", signoutHandler)
	r.HandleFunc("/mypage", mypageHandler)
	r.HandleFunc("/memo/{memo_id}", memoHandler).Methods("GET", "HEAD")
	r.HandleFunc("/memo", memoPostHandler).Methods("POST")
	r.HandleFunc("/recent/{page:[0-9]+}", recentHandler)
	r.HandleFunc("/__reset__", resetHandler)
	initStaticFiles(r, "public")
	http.Handle("/", r)
	go fillRecentCache()
	log.Fatal(http.ListenAndServe(listenAddr, nil))
}

func loadConfig(filename string) *Config {
	log.Printf("loading config file: %s", filename)
	f, err := ioutil.ReadFile(filename)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	var config Config
	err = json.Unmarshal(f, &config)
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}
	return &config
}

func prepareHandler(w http.ResponseWriter, r *http.Request) *url.URL {
	var baseUrl *url.URL
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		baseUrl, _ = url.Parse("http://" + h)
	} else {
		baseUrl, _ = url.Parse("http://" + r.Host)
	}
	return baseUrl
}

func getUser(w http.ResponseWriter, r *http.Request, session *Session) *User {
	userId := session.UserId
	if userId == 0 {
		return nil
	}
	user := M.users[userId]
	if user != nil {
		w.Header().Add("Cache-Control", "private")
	}
	return user
}

func antiCSRF(w http.ResponseWriter, r *http.Request, session *Session) bool {
	if r.FormValue("sid") != session.Token {
		log.Println("CSRF ERROR", r.FormValue("sid"), session.Token)
		code := http.StatusBadRequest
		http.Error(w, http.StatusText(code), code)
		return true
	}
	return false
}

func serverError(w http.ResponseWriter, err error) {
	log.Printf("error: %s", err)
	code := http.StatusInternalServerError
	http.Error(w, http.StatusText(code), code)
}

func notFound(w http.ResponseWriter) {
	code := http.StatusNotFound
	http.Error(w, http.StatusText(code), code)
}

func topHandler(w http.ResponseWriter, r *http.Request) {
	recentPageHandler(w, r, 0)
}

func recentPageCache(publicMemos []*Memo, page int) {
	nMemos := len(publicMemos)
	cnt := nMemos - (page * memosPerPage)
	if cnt > memosPerPage {
		cnt = memosPerPage
	}
	if cnt == 0 {
		return
	}

	buf := recentPageBufferPool.Get().(*bytes.Buffer)
	memos := make([]*Memo, cnt)
	offset := len(publicMemos) - memosPerPage*page - 1
	for i := 0; i < cnt; i++ {
		memos[i] = publicMemos[offset-i]
	}
	v := &View{
		Total:     nMemos,
		Page:      page,
		PageStart: memosPerPage*page + 1,
		PageEnd:   memosPerPage * (page + 1),
		Memos:     memos,
		User:      nil,
		Session:   nil,
		BaseUrl:   "",
	}
	renderIndex(buf, v)
	M.recentPageCache[page] = PageCache{buf.String(), time.Now().Add(time.Second).UnixNano()}
	buf.Reset()
	recentPageBufferPool.Put(buf)
}

func fillRecentCache() {
	for {
		publicMemos := M.publicMemos[:]
		pages := (len(publicMemos) + (memosPerPage - 1)) / memosPerPage
		for i := 0; i < pages; i++ {
			recentPageCache(publicMemos, i)
		}
		time.Sleep(time.Millisecond * 700)
	}
}

var recentPageBufferPool sync.Pool = sync.Pool{New: func() interface{} { return &bytes.Buffer{} }}

func recentPageHandler(w http.ResponseWriter, r *http.Request, page int) {
	session := sessionStore.Get(r)
	baseUrl := prepareHandler(w, r)
	user := getUser(w, r, session)

	v := &View{
		Total:     len(M.publicMemos),
		Page:      page,
		PageStart: memosPerPage*page + 1,
		PageEnd:   memosPerPage * (page + 1),
		Memos:     nil,
		User:      user,
		Session:   session,
		BaseUrl:   baseUrl.String(),
	}

	cache := M.recentPageCache[page]
	buf := recentPageBufferPool.Get().(*bytes.Buffer)
	if user == nil {
		buf.WriteString(anonymousHeader)
	} else {
		renderTop(buf, v)
	}
	buf.WriteString(cache.page)
	w.Header().Set("Content-Length", strconv.Itoa(buf.Len()))
	w.Write(buf.Bytes())
	buf.Reset()
	recentPageBufferPool.Put(buf)
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	initialLoad()
	io.WriteString(w, "OK")
}

func recentHandler(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	page, _ := strconv.Atoi(vars["page"])
	recentPageHandler(w, r, page)
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
	//defer func(t time.Time) { log.Println("signin", time.Now().Sub(t)) }(time.Now())
	session := sessionStore.Get(r)
	baseUrl := prepareHandler(w, r)
	user := getUser(w, r, session)

	v := &View{
		User:    user,
		Session: session,
		BaseUrl: baseUrl.String(),
	}
	if err := tmpl.ExecuteTemplate(w, "signin", v); err != nil {
		serverError(w, err)
		return
	}
}

func signinPostHandler(w http.ResponseWriter, r *http.Request) {
	//defer func(t time.Time) { log.Println("signin post", time.Now().Sub(t)) }(time.Now())
	session := sessionStore.Get(r)
	baseUrl := prepareHandler(w, r)

	username := r.FormValue("username")
	password := r.FormValue("password")

	var user *User
	for _, user = range M.users {
		if user != nil && user.Username == username {
			break
		}
	}
	if user != nil && user.Username == username {
		h := sha256.New()
		h.Write([]byte(user.Salt + password))
		if user.Password == fmt.Sprintf("%x", h.Sum(nil)) {
			session.UserId = user.Id
			session.Token = fmt.Sprintf("%x", securecookie.GenerateRandomKey(32))
			sessionStore.Set(w, session)
			http.Redirect(w, r, "/mypage", http.StatusFound)
			return
		}
	}
	v := &View{
		Session: session,
		BaseUrl: baseUrl.String(),
	}
	if err := tmpl.ExecuteTemplate(w, "signin", v); err != nil {
		serverError(w, err)
		return
	}
}

func signoutHandler(w http.ResponseWriter, r *http.Request) {
	//defer func(t time.Time) { log.Println("signout post", time.Now().Sub(t)) }(time.Now())
	session := sessionStore.Get(r)
	if antiCSRF(w, r, session) {
		return
	}

	http.SetCookie(w, sessions.NewCookie(sessionName, "", &sessions.Options{MaxAge: -1}))
	http.Redirect(w, r, "/", http.StatusFound)
}

func mypageHandler(w http.ResponseWriter, r *http.Request) {
	//defer func(t time.Time) { log.Println("mypage", time.Now().Sub(t)) }(time.Now())
	session := sessionStore.Get(r)
	baseUrl := prepareHandler(w, r)

	user := getUser(w, r, session)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	myMemos := memosForUser.GetMemo(user.Id)
	v := &View{
		Memos:   myMemos,
		User:    user,
		Session: session,
		BaseUrl: baseUrl.String(),
	}
	buf := bytes.Buffer{}
	renderMypage(&buf, v)
	w.Write(buf.Bytes())
}

func memoHandler(w http.ResponseWriter, r *http.Request) {
	//time.Sleep(100 * time.Millisecond)
	//defer func(t time.Time) { log.Println("memo", time.Now().Sub(t)) }(time.Now())
	session := sessionStore.Get(r)
	baseUrl := prepareHandler(w, r)
	vars := mux.Vars(r)
	var memoId int
	fmt.Sscanf(vars["memo_id"], "%d", &memoId)

	M.lock.RLock()
	defer M.lock.RUnlock()

	user := getUser(w, r, session)
	if memoId >= len(M.memos) {
		notFound(w)
		return
	}
	memo := M.memos[memoId]
	if memo == nil {
		notFound(w)
		return
	}

	if memo.IsPrivate == 1 {
		if user == nil || user.Id != memo.User {
			notFound(w)
			return
		}
	}

	var older, newer *Memo
	prevId := memo.prevId
	for prevId > 0 {
		p := M.memos[prevId]
		if p.IsPrivate == 0 || (user != nil && user.Id == p.User) {
			older = p
			break
		}
		prevId = p.prevId
	}
	nextId := memo.nextId
	for nextId > 0 {
		p := M.memos[nextId]
		if p.IsPrivate == 0 || (user != nil && user.Id == p.User) {
			newer = p
			break
		}
		nextId = p.nextId
	}

	v := &View{
		User:    user,
		Memo:    memo,
		Older:   older,
		Newer:   newer,
		Session: session,
		BaseUrl: baseUrl.String(),
	}
	if err := tmpl.ExecuteTemplate(w, "memo", v); err != nil {
		serverError(w, err)
	}
}

func memoPostHandler(w http.ResponseWriter, r *http.Request) {
	//defer func(t time.Time) { log.Println("memo post", time.Now().Sub(t)) }(time.Now())
	session := sessionStore.Get(r)
	if antiCSRF(w, r, session) {
		return
	}

	user := getUser(w, r, session)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}
	var isPrivate int
	if r.FormValue("is_private") == "1" {
		isPrivate = 1
	} else {
		isPrivate = 0
	}
	now := time.Now().Format("2006-01-02 15:04:05")
	result, err := insertMemoStmt.Exec(user.Id, r.FormValue("content"), isPrivate, now)
	if err != nil {
		serverError(w, err)
		return
	}
	newId, _ := result.LastInsertId()

	M.lock.Lock()
	memo := &Memo{
		Id:        int(newId),
		User:      user.Id,
		Content:   r.FormValue("content"),
		IsPrivate: isPrivate,
		CreatedAt: now,
		UpdatedAt: now,
		Username:  user.Username}
	addMemo(memo)
	M.lock.Unlock()

	http.Redirect(w, r, fmt.Sprintf("/memo/%d", newId), http.StatusFound)
}

func initialLoad() {
	M.lock.Lock()
	defer M.lock.Unlock()

	rows, err := DB.Query("SELECT id, username, password, salt FROM users")
	must(err)
	for rows.Next() {
		user := &User{}
		rows.Scan(&user.Id, &user.Username, &user.Password, &user.Salt)
		M.users[user.Id] = user
	}
	rows.Close()

	memosForUser.Reset()
	M.memos = []*Memo{}
	M.publicMemos = []*Memo{}
	M.maxMemoId = 0
	rows, err = DB.Query("SELECT id, user, content, is_private, created_at, updated_at FROM memos")
	must(err)
	for rows.Next() {
		memo := &Memo{}
		rows.Scan(&memo.Id, &memo.User, &memo.Content, &memo.IsPrivate, &memo.CreatedAt, &memo.UpdatedAt)
		memo.Username = M.users[memo.User].Username
		//log.Println("memo:", memo.Id)
		addMemo(memo)
		markdownConvertChan <- memo
	}
	rows.Close()
}

func initStaticFiles(r *mux.Router, prefix string) {
	wf := func(path string, info os.FileInfo, err error) error {
		log.Println(path, info, err)
		if path == prefix {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		urlpath := path[len(prefix):]
		if urlpath[0] != '/' {
			urlpath = "/" + urlpath
		}
		log.Println("Registering", urlpath, path)
		f, err := os.Open(path)
		if err != nil {
			log.Println(err)
			return nil
		}
		content := make([]byte, info.Size())
		f.Read(content)
		f.Close()

		handler := func(w http.ResponseWriter, r *http.Request) {
			if strings.HasSuffix(path, ".css") {
				w.Header().Set("Content-Type", "text/css")
			} else if strings.HasSuffix(path, ".js") {
				w.Header().Set("Content-Type", "application/javascript")
			}
			w.Header().Set("Content-Length", strconv.FormatInt(int64(len(content)), 10))
			w.Write(content)
		}
		http.HandleFunc(urlpath, handler)
		//r.HandleFunc(urlpath, handler)
		return nil
	}
	filepath.Walk(prefix, wf)
}

func renderTop(w io.Writer, v *View) {
	if v.User == nil && anonymousHeader != "" {
		io.WriteString(w, anonymousHeader)
		return
	}
	io.WriteString(w, `<!DOCTYPE html>
<html>
<head>
<meta http-equiv="Content-Type" content="text/html" charset="utf-8">
<title>Isucon3</title>
<link rel="stylesheet" href="/css/bootstrap.min.css">
<style>
body {padding-top: 60px;}
</style>
</head>
<body>
<div class="navbar navbar-fixed-top">
<div class="navbar-inner">
<div class="container">
<a class="btn btn-navbar" data-toggle="collapse" data-target=".nav-collapse">
<span class="icon-bar"></span>
<span class="icon-bar"></span>
<span class="icon-bar"></span>
</a>
<a class="brand" href="/">Isucon3</a>
<div class="nav-collapse">
<ul class="nav">
<li><a href="`+v.BaseUrl+`/">Home</a></li>`)
	if v.User != nil {
		io.WriteString(w, `
<li><a href="`+v.BaseUrl+`/mypage">MyPage</a></li>
<li>
<form action="/signout" method="post">
<input type="hidden" name="sid" value="`+v.Session.Token+`">
<input type="submit" value="SignOut">
</form>
</li>`)
	} else {
		fmt.Fprintf(w, `<li><a href="%s/signin">SignIn</a></li>`, v.BaseUrl)
	}
	io.WriteString(w, `</ul>
</div> <!--/.nav-collapse -->
</div></div></div>

<div class="container">
<h2>Hello `)
	if v.User != nil {
		io.WriteString(w, v.User.Username)
	}
	io.WriteString(w, "!</h2>")
}

func renderBottom(w io.Writer, v *View) {
	io.WriteString(w, `</div>
<script type="text/javascript" src="/js/jquery.min.js"></script>
<script type="text/javascript" src="/js/bootstrap.min.js"></script>
</body></html>`)
}

func renderIndex(w *bytes.Buffer, v *View) error {
	//buf := &bytes.Buffer{}
	//renderTop(buf, v)
	fmt.Fprintf(w, `<h3>public memos</h3>
<p id="pager">
  recent %d - %d / total <span id="total">%d</span>
</p>
<ul id="memos">`, v.PageStart, v.PageEnd, v.Total)

	for _, memo := range v.Memos {
		w.WriteString(memo.titleLi)
	}
	w.WriteString(`</ul>`)
	w.WriteString(footer)
	return nil
}

func renderMypage(w io.Writer, v *View) {
	renderTop(w, v)
	fmt.Fprintf(w, `
<form action="/memo" method="post">
  <input type="hidden" name="sid" value="%s">
  <textarea name="content"></textarea>
  <br>
  <input type="checkbox" name="is_private" value="1"> private
  <input type="submit" value="post">
</form>

<h3>my memos</h3>

<ul>`, v.Session.Token)

	for i := len(v.Memos) - 1; i >= 0; i-- {
		memo := v.Memos[i]
		private := ""
		if memo.IsPrivate != 0 {
			private = "[private]"
		}
		fmt.Fprintf(w, `<li>
<a href="/memo/%d">%s</a> by %s (%s)
  %s
</li>
</ul>
`, memo.Id, memo.firstline, html.EscapeString(memo.Username), memo.CreatedAt, private)
	}
	renderBottom(w, v)
}
