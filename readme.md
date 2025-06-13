# 備註

- 內部部署: app.py
- 客戶端部署: app_dist.py
  ** 寫/讀檔都用 utf-8
  ** 去除 cross domain , 因為客戶環境有架 nginx,nginx 已有設定, 再設會衝突

- 注意事項
  ** 不能直接蓋掉客戶端的 app.py
  ** 要先比對 app_dist.py , 再進行更新
