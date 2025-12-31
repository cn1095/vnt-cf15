```
# 本地测试
cd vnts-ws-relay
sudo docker build -t vnts-ws-relay .

sudo docker run -it -p 29872:8787 -v $(pwd):/app -v /app/node_modules vnts-ws-relay
```
