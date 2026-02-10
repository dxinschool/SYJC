批量提交說明：
批量提交Flag API如下所示，該接口限制了每秒訪問次數(10tps)
參賽Token：
67b0d49867ee5e16595959bac3fd1520
提交地址：
http://10.2.60.1/api/ct/web/awd_race/race/26c4e794b2f1612181e55422e8ddc718/flag/robot/
API詳情：
POST http://10.2.60.1/api/ct/web/awd_race/race/26c4e794b2f1612181e55422e8ddc718/flag/robot/

Request Headers：
Content-Type: application/json

Request Body：
{
  "flag": "flag{xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx}",
  "token": "67b0d49867ee5e16595959bac3fd1520"
}

Response Body：
{
  "code": "AD-000000",
  "message": "",
  "detail": "",
  "timestamp": 1665595188.435406,
  "data": { "is_pass": true, "is_duplicate": true }
}

