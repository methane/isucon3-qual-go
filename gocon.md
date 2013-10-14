# ISUCON3 予選に Go で参戦した

See also [ISUCON3予選参戦記](http://dsas.blog.klab.org/archives/52127178.html)

## ISUCON とは (2min)

NHN 主催のチューニング大会 (II kanji ni Speed Up CONtest)
今回は出題を KAYAC が担当

リファレンスとなるWebアプリ/構成を制限時間内にチューニング.

ルール:
* ベンチマークツールのテストと、Webブラウザによるチェックを通る
* サーバーを再起動してもデータが飛ばない
* イスを投げない

## ISUCON 1  (2min)

(未参戦)

* Blog アプリ
* 最近コメントされた記事一覧がサイドバーにある
* 負荷はかなり偏ってる
* POST, Comment の結果は1秒間その他のGETに反映されなくても良い

解法: ページとサイドバーを別々にキャッシュし、Webサーバー内で結合

## ISUCON 2

### 準備 (2min)

目標: リバースプロキシを外し、1台で最高性能を.

* Python の Web サーバー meinheld を nginx 並に速く
* Go 1.0 が遅かったので syscall や net/http の高速化
* 低レイヤ好きとチームになったのでカーネル空間で動く Web サーバー+memcachedを作成

### 本戦 (2min)

* チケット販売サイト
* チケット販売速度とその他のPV/secがスコア(チケット販売が支配的)
* POST, Comment の結果は1秒間その他のGETに反映されなくても良い

結果: 環境のカーネルが古く、入れ替えて再起動不能に.

解法: ページ数が少ないので全ページを1秒ごとに再生成

## ISUCON と Go (4min)

基本的に優勝するにはフロント (nginx) でキャッシュを配信する構成をとる必要がある.

フロントを担当できる (静的ファイル配信が高速. KeepAlive対応. Slowloris対策)
と、リバースプロキシのオーバーヘッドがなくて済むので強い.

* Go
* OpenResty (nginx)
* node.js
* Meinheld, Tornado + PyPy

Go 以外はすべて、マルチコアを使うのにマルチプロセスが必要

* メモリ使用量
* プロセス間通信のオーバーヘッド

の観点で Go は有利.


## ISUCON 3 予選

### 準備 (1min)

KLab から2チーム出場するので, ISUCON 2のおさらい

Go で ISUCON 2 の実装

### 予選 (2min)

* 指定されたAMIを高速化し、AMIを提出するオンライン方式
* Gist 風の Markdown でかけるオンラインメモアプリ
* POST, Comment の結果は1秒間その他のGETに反映されなくても良い
* ログインあり

メモリに乗り切るので、DBへのアクセスは書き込みだけ

ログイン状態によって異なる部分を考慮したページキャッシュ

### コードリーディング (2min)

[github.com/methane/isucon3-qual-go](https://github.com/methane/isucon3-qual-go)

データ管理

ページキャッシュ

## ISUCON 3 本戦に向けて (2min)

予選は1台だったけど、本戦は複数台構成

* reverse proxy
* rpc
* groupcache
* PubSub

## まとめ

Go はミドルウェアとアプリの垣根を取り払ってくれる
ISUCON 向き
よりよいアーキテクチャを探求できる

みんな Go を使って ISUCON に出よう!
