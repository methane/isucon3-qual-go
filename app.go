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
	"github.com/knieriem/markdown"
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
	memosPerPage    = 100
	listenAddr      = ":80"
	sessionName     = "isucon_session"
	tmpDir          = "/tmp/"
	markdownCommand = "../bin/markdown"
	memcachedServer = "localhost:11211"
)

func must(err error) {
	if err != nil {
		log.Panic(err)
	}
}

func sql_escape(s string) string {
	return strings.Replace(s, "'", "''", -1)
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
	store map[string]*Session
	lock  sync.Mutex
}

var sessionStore = SessionStore{
	make(map[string]*Session),
	sync.Mutex{},
}

func (self SessionStore) Get(r *http.Request) *Session {
	cookie, _ := r.Cookie(sessionName)
	if cookie == nil {
		return &Session{}
	}
	self.lock.Lock()
	defer self.lock.Unlock()
	key := cookie.Value
	s := self.store[key]
	if s == nil {
		s = &Session{}
	}
	return s
}

func (self SessionStore) Set(w http.ResponseWriter, sess *Session) {
	key := sess.Key
	if key == "" {
		b := make([]byte, 8)
		rand.Read(b)
		key = hex.EncodeToString(b)
		sess.Key = key
	}

	cookie := sessions.NewCookie(sessionName, key, &sessions.Options{})
	http.SetCookie(w, cookie)

	self.lock.Lock()
	defer self.lock.Unlock()
	self.store[key] = sess
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
	mlock     sync.Mutex
}

type Memos []*Memo

type View struct {
	User      *User
	Memo      *Memo
	Memos     *Memos
	Page      int
	PageStart int
	PageEnd   int
	Total     int
	Older     *Memo
	Newer     *Memo
	Session   *Session
	BaseUrl   string
}

var M = struct {
	lock            sync.RWMutex
	users           map[int]*User
	memos           []*Memo
	publicMemoCount int
	maxMemoId       int
}{
	lock:            sync.RWMutex{},
	users:           make(map[int]*User, 100),
	memos:           []*Memo{},
	publicMemoCount: 0,
	maxMemoId:       0,
}

func addMemo(memo *Memo) {
	if len(M.memos) < memo.Id+1 {
		t := make([]*Memo, memo.Id*2+5)
		copy(t, M.memos)
		M.memos = t
	}
	if M.memos[memo.Id] == nil && memo.IsPrivate == 0 {
		M.publicMemoCount++
	}
	M.memos[memo.Id] = memo
	if memo.Id > M.maxMemoId {
		M.maxMemoId = memo.Id
	}
}

var (
	DB      *sql.DB
	baseUrl *url.URL
	fmap    = template.FuncMap{
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

func (memo *Memo) Markdown() template.HTML {
	memo.mlock.Lock()
	defer memo.mlock.Unlock()

	if memo.markdown == template.HTML("") {
		p := markdown.NewParser(&markdown.Extensions{})
		bo := bytes.Buffer{}
		bi := bytes.NewBufferString(memo.Content)
		p.Markdown(bi, markdown.ToHTML(&bo))
		memo.markdown = template.HTML(bo.String())
	}
	return memo.markdown
}

func init() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
}

func main() {
	env := os.Getenv("ISUCON_ENV")
	if env == "" {
		env = "local"
	}
	config := loadConfig("../config/" + env + ".json")
	db := config.Database
	connectionString := fmt.Sprintf(
		"%s:%s@tcp(%s:%d)/%s?charset=utf8&sql_mode=NO_BACKSLASH_ESCAPES",
		db.Username, db.Password, db.Host, db.Port, db.Dbname,
	)
	log.Printf("db: %s", connectionString)

	var err error
	DB, err = sql.Open("mysql", connectionString)
	if err != nil {
		log.Panic(err)
	}
	DB.SetMaxIdleConns(256)

	initialLoad()

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

func prepareHandler(w http.ResponseWriter, r *http.Request) {
	if h := r.Header.Get("X-Forwarded-Host"); h != "" {
		baseUrl, _ = url.Parse("http://" + h)
	} else {
		baseUrl, _ = url.Parse("http://" + r.Host)
	}
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
	//defer func(t time.Time) { log.Println("top", time.Now().Sub(t)) }(time.Now())
	session := sessionStore.Get(r)
	prepareHandler(w, r)

	M.lock.RLock()
	defer M.lock.RUnlock()

	user := getUser(w, r, session)

	memos := make(Memos, 0, memosPerPage)
	i := M.maxMemoId
	for len(memos) < memosPerPage {
		if i <= 0 {
			break
		}
		m := M.memos[i]
		i--
		if m == nil || m.IsPrivate != 0 {
			continue
		}
		memos = append(memos, m)
	}

	v := &View{
		Total:     M.publicMemoCount,
		Page:      0,
		PageStart: 1,
		PageEnd:   memosPerPage,
		Memos:     &memos,
		User:      user,
		Session:   session,
		BaseUrl:   baseUrl.String(),
	}
	if err := tmpl.ExecuteTemplate(w, "index", v); err != nil {
		serverError(w, err)
	}
}

func resetHandler(w http.ResponseWriter, r *http.Request) {
	initialLoad()
	io.WriteString(w, "OK")
}

func recentHandler(w http.ResponseWriter, r *http.Request) {
	session := sessionStore.Get(r)
	prepareHandler(w, r)
	user := getUser(w, r, session)
	vars := mux.Vars(r)
	page, _ := strconv.Atoi(vars["page"])

	M.lock.RLock()
	defer M.lock.RUnlock()

	memos := make(Memos, 0, memosPerPage)
	i := M.maxMemoId
	skip := memosPerPage * page
	for len(memos) < memosPerPage {
		if i <= 0 {
			break
		}
		m := M.memos[i]
		i--
		if m == nil || m.IsPrivate != 0 {
			continue
		}
		if skip > 0 {
			skip--
			continue
		}
		memos = append(memos, m)
	}

	if len(memos) == 0 {
		notFound(w)
		return
	}

	v := &View{
		Total:     M.publicMemoCount,
		Page:      page,
		PageStart: memosPerPage*page + 1,
		PageEnd:   memosPerPage * (page + 1),
		Memos:     &memos,
		User:      user,
		Session:   session,
		BaseUrl:   baseUrl.String(),
	}
	if err := tmpl.ExecuteTemplate(w, "index", v); err != nil {
		serverError(w, err)
	}
}

func signinHandler(w http.ResponseWriter, r *http.Request) {
	//defer func(t time.Time) { log.Println("signin", time.Now().Sub(t)) }(time.Now())
	session := sessionStore.Get(r)
	prepareHandler(w, r)
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
	prepareHandler(w, r)

	username := r.FormValue("username")
	password := r.FormValue("password")

	M.lock.RLock()
	defer M.lock.RUnlock()
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
	prepareHandler(w, r)
	if antiCSRF(w, r, session) {
		return
	}

	http.SetCookie(w, sessions.NewCookie(sessionName, "", &sessions.Options{MaxAge: -1}))
	http.Redirect(w, r, "/", http.StatusFound)
}

func mypageHandler(w http.ResponseWriter, r *http.Request) {
	//defer func(t time.Time) { log.Println("mypage", time.Now().Sub(t)) }(time.Now())
	session := sessionStore.Get(r)
	prepareHandler(w, r)

	M.lock.RLock()
	defer M.lock.RUnlock()

	user := getUser(w, r, session)
	if user == nil {
		http.Redirect(w, r, "/", http.StatusFound)
		return
	}

	memos := make(Memos, 0, memosPerPage)
	i := M.maxMemoId
	for len(memos) < memosPerPage {
		if i <= 0 {
			break
		}
		m := M.memos[i]
		i--
		if m == nil || m.User != user.Id {
			continue
		}
		memos = append(memos, m)
	}
	v := &View{
		Memos:   &memos,
		User:    user,
		Session: session,
		BaseUrl: baseUrl.String(),
	}
	if err := tmpl.ExecuteTemplate(w, "mypage", v); err != nil {
		serverError(w, err)
	}
}

func memoHandler(w http.ResponseWriter, r *http.Request) {
	//defer func(t time.Time) { log.Println("memo", time.Now().Sub(t)) }(time.Now())
	session := sessionStore.Get(r)
	prepareHandler(w, r)
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
	current := memo.Id - 1
	for current > 0 {
		m := M.memos[current]
		current--

		if m == nil || m.User != memo.User {
			continue
		}
		if user == nil || user.Id != memo.User {
			if m.IsPrivate != 0 {
				continue
			}
		}
		older = m
		break
	}
	current = memo.Id + 1
	for current+1 < len(M.memos) {
		m := M.memos[current]
		current++

		if m == nil || m.User != memo.User {
			continue
		}
		if user == nil || user.Id != memo.User {
			if m.IsPrivate != 0 {
				continue
			}
		}
		newer = m
		break
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
	prepareHandler(w, r)
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
	result, err := DB.Exec(
		fmt.Sprintf("INSERT INTO memos (user, content, is_private, created_at) VALUES (%d, '%s', %d, '%s')",
			user.Id, sql_escape(r.FormValue("content")), isPrivate, now))
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

	M.memos = []*Memo{}
	M.publicMemoCount = 0
	M.maxMemoId = 0
	rows, err = DB.Query("SELECT id, user, content, is_private, created_at, updated_at FROM memos")
	must(err)
	for rows.Next() {
		memo := &Memo{}
		rows.Scan(&memo.Id, &memo.User, &memo.Content, &memo.IsPrivate, &memo.CreatedAt, &memo.UpdatedAt)
		memo.Username = M.users[memo.User].Username
		log.Println("memo:", memo.Id)
		addMemo(memo)
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
			if path[len(path)-4:] == ".css" {
				w.Header().Set("Content-Type", "text/css")
			} else if path[len(path)-3:] == ".js" {
				w.Header().Set("Content-Type", "application/javascript")
			}
			w.Write(content)
		}
		r.HandleFunc(urlpath, handler)
		return nil
	}
	filepath.Walk(prefix, wf)
}
