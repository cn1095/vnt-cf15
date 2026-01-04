javascript版vnts实现，cloudflare worker

```
# 本地测试
cd vnts-ws-relay
sudo docker build -t vnts-ws-relay .

sudo rm -rf node_modules .wrangler
sudo docker run --rm -it -p 29872:8787 -v $(pwd):/app -v /app/node_modules vnts-ws-relay
```

```
# 删除未使用卷
sudo docker volume prune
```

```
#安装旧版本 格式化
npm install -g prettier@2.8.8
prettier --write *.js
```
