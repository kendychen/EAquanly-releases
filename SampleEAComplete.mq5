//+------------------------------------------------------------------+
//|  SampleEAComplete.mq5 — EA template TOÀN TRONG 1 FILE             |
//|                                                                  |
//|  Tích hợp sẵn:                                                   |
//|    1) License verify HMAC + anti rollback đồng hồ (chống share)   |
//|    2) Live publisher — push snapshot/positions/trades đã đóng    |
//|       lên backend để /live/<slug> + dashboard admin hiển thị     |
//|    3) Trading logic stub — chỗ viết chiến lược thực               |
//|                                                                  |
//|  KHÔNG CẦN FILE PHỤ — copy 1 file này vào MQL5/Experts/ là đủ.   |
//|                                                                  |
//|  KHÁCH HÀNG SETUP:                                                |
//|    - Tools > Options > Expert Advisors > Allow WebRequest, thêm   |
//|      URL server (vd https://buyeaql.com hoặc IP:port).           |
//|    - Đổi EA_SLUG dưới đây cho khớp ea_products.slug trên admin.  |
//|    - F7 compile.                                                  |
//|    - Kéo EA vào chart → tab Inputs:                              |
//|        LicenseKey  — admin cấp khi mua EA                        |
//|        Live Slug + Secret — admin cấp ở Admin > Live Accounts    |
//|        Để trống Live * → bỏ qua publish, chỉ check license.      |
//+------------------------------------------------------------------+
#property strict
#property copyright "EA SELLER"
#property version   "1.10"
#property description "EA template — license check + live publish + trading stub (all-in-one)"

// === Slug EA, phải khớp ea_products.slug trên admin web ===
#define EA_SLUG "my-sample-ea"

// ============ INPUTS ============
input group "── License (bắt buộc) ──"
input string InpLicenseServer   = "https://buyeaql.com";              // Server URL — KHÔNG / cuối
input string InpLicenseSecret   = "change_me_to_random_32_bytes_hex"; // LICENSE_HMAC_SECRET trong .env server
input string InpLicenseKey      = "EA-XXXX-XXXX-XXXX-XXXX";           // License key khách dán

input group "── Live Publisher (tuỳ chọn) ──"
input string InpLiveServer      = "";                                 // Vd https://buyeaql.com (trống → bỏ qua)
input string InpLiveSlug        = "";                                 // Slug account ở Admin > Live Accounts
input string InpLiveSecret      = "";                                 // Ingest secret 64-hex từ admin
input int    InpLivePushSec     = 5;                                  // Tần suất push (giây)
input int    InpLiveHistoryDays = 7;                                  // Quét lịch sử N ngày
input string InpLiveEaVersion   = "1.0.0";                            // Tag version để debug

input group "── Trading logic ──"
input double InpLotSize         = 0.10;                               // Volume mặc định
input int    InpMagicNumber     = 770123;                             // Magic number cho lệnh của EA này


// ============================================================
// HMAC-SHA256 implementation
// MQL5 CryptEncode(CRYPT_HASH_SHA256) chỉ làm SHA256, IGNORE param key,
// nên phải tự ráp HMAC = SHA256( (K' XOR opad) || SHA256( (K' XOR ipad) || msg ) ).
// ============================================================
bool Sha256Bytes(const uchar &data[], uchar &out[])
{
   uchar dummyKey[];
   return CryptEncode(CRYPT_HASH_SHA256, data, dummyKey, out) > 0;
}

bool HmacSha256(const uchar &key[], const uchar &message[], uchar &result[])
{
   const int BLOCK_SIZE = 64;
   const int HASH_SIZE  = 32;

   uchar normKey[];
   ArrayResize(normKey, BLOCK_SIZE);
   ArrayInitialize(normKey, 0);

   int keyLen = ArraySize(key);
   if(keyLen > BLOCK_SIZE)
   {
      uchar hashedKey[];
      if(!Sha256Bytes(key, hashedKey)) return false;
      ArrayCopy(normKey, hashedKey, 0, 0, HASH_SIZE);
   }
   else
   {
      ArrayCopy(normKey, key, 0, 0, keyLen);
   }

   uchar ipad[], opad[];
   ArrayResize(ipad, BLOCK_SIZE);
   ArrayResize(opad, BLOCK_SIZE);
   for(int i = 0; i < BLOCK_SIZE; i++)
   {
      ipad[i] = (uchar)(normKey[i] ^ 0x36);
      opad[i] = (uchar)(normKey[i] ^ 0x5c);
   }

   int msgLen = ArraySize(message);
   uchar innerInput[];
   ArrayResize(innerInput, BLOCK_SIZE + msgLen);
   ArrayCopy(innerInput, ipad, 0, 0, BLOCK_SIZE);
   if(msgLen > 0) ArrayCopy(innerInput, message, BLOCK_SIZE, 0, msgLen);

   uchar innerHash[];
   if(!Sha256Bytes(innerInput, innerHash)) return false;

   uchar outerInput[];
   ArrayResize(outerInput, BLOCK_SIZE + HASH_SIZE);
   ArrayCopy(outerInput, opad, 0, 0, BLOCK_SIZE);
   ArrayCopy(outerInput, innerHash, BLOCK_SIZE, 0, HASH_SIZE);

   return Sha256Bytes(outerInput, result);
}

string BytesToHex(const uchar &arr[])
{
   string hex = "";
   for(int i = 0; i < ArraySize(arr); i++) hex += StringFormat("%02x", arr[i]);
   return hex;
}

string Sha256Hex(const string s)
{
   uchar in[], out[];
   StringToCharArray(s, in, 0, StringLen(s));
   if(!Sha256Bytes(in, out)) return "";
   return BytesToHex(out);
}

string Hmac256Hex(const string secret, const string data)
{
   uchar key[], msg[], out[];
   StringToCharArray(secret, key, 0, StringLen(secret));
   StringToCharArray(data,   msg, 0, StringLen(data));
   if(!HmacSha256(key, msg, out)) return "";
   return BytesToHex(out);
}


// ============================================================
// JSON helpers
// ============================================================
string JsonStr(const string s)
{
   string r = s;
   StringReplace(r, "\\", "\\\\");
   StringReplace(r, "\"", "\\\"");
   StringReplace(r, "\r", " ");
   StringReplace(r, "\n", " ");
   return "\"" + r + "\"";
}

bool JsonField(const string body, const string key, string &out_val)
{
   string needle = "\"" + key + "\":";
   int p = StringFind(body, needle);
   if(p < 0) return false;
   p += StringLen(needle);
   while(p < StringLen(body) && (StringGetCharacter(body, p) == ' ' || StringGetCharacter(body, p) == '\t')) p++;
   if(p >= StringLen(body)) return false;
   ushort ch = StringGetCharacter(body, p);
   if(ch == '"')
   {
      int e = StringFind(body, "\"", p + 1);
      if(e < 0) return false;
      out_val = StringSubstr(body, p + 1, e - p - 1);
      return true;
   }
   int e = p;
   while(e < StringLen(body))
   {
      ushort c = StringGetCharacter(body, e);
      if(c == ',' || c == '}' || c == ' ' || c == '\r' || c == '\n') break;
      e++;
   }
   out_val = StringSubstr(body, p, e - p);
   return true;
}

// "2026-12-31T23:59:59Z" → datetime GMT. Trả 0 nếu format sai.
datetime ParseIso8601(const string s)
{
   if(StringLen(s) < 19) return 0;
   int Y = (int)StringToInteger(StringSubstr(s, 0, 4));
   int M = (int)StringToInteger(StringSubstr(s, 5, 2));
   int D = (int)StringToInteger(StringSubstr(s, 8, 2));
   int h = (int)StringToInteger(StringSubstr(s, 11, 2));
   int m = (int)StringToInteger(StringSubstr(s, 14, 2));
   int sec = (int)StringToInteger(StringSubstr(s, 17, 2));
   if(Y < 2020 || Y > 2100) return 0;
   if(M < 1 || M > 12 || D < 1 || D > 31) return 0;
   MqlDateTime dt;
   dt.year = Y; dt.mon = M; dt.day = D;
   dt.hour = h; dt.min = m; dt.sec = sec;
   return StructToTime(dt);
}

string IsoTime(const datetime t)
{
   if(t == 0) return "";
   MqlDateTime dt; TimeToStruct(t, dt);
   return StringFormat("%04d-%02d-%02dT%02d:%02d:%02dZ",
                       dt.year, dt.mon, dt.day, dt.hour, dt.min, dt.sec);
}


// ============================================================
// License verify — gọi server 1 lần lúc OnInit. Sau đó check expiry LOCAL.
// Trả true nếu hợp lệ, out_expires_at = 0 nghĩa là vĩnh viễn.
// ============================================================
bool LicenseVerify(const string license_key, string &out_err, datetime &out_expires_at)
{
   out_expires_at = 0;
   long   account = AccountInfoInteger(ACCOUNT_LOGIN);
   string broker  = AccountInfoString(ACCOUNT_COMPANY);
   long   ts      = (long)TimeGMT();

   string acct_str = IntegerToString(account);
   string canonical = license_key + "|" + acct_str + "|" + broker + "|" + EA_SLUG + "|" + IntegerToString(ts);
   string signature = Hmac256Hex(InpLicenseSecret, canonical);

   string body = "{";
   body += "\"license_key\":" + JsonStr(license_key) + ",";
   body += "\"mt_account\":"  + JsonStr(acct_str)    + ",";
   body += "\"broker\":"      + JsonStr(broker)      + ",";
   body += "\"ea_slug\":"     + JsonStr(EA_SLUG)     + ",";
   body += "\"timestamp\":"   + IntegerToString(ts)  + ",";
   body += "\"signature\":"   + JsonStr(signature);
   body += "}";

   char post[], result[];
   int bodyLen = StringLen(body);
   ArrayResize(post, bodyLen);
   StringToCharArray(body, post, 0, bodyLen);

   string headers = "Content-Type: application/json\r\n";
   string url = InpLicenseServer + "/api/license/verify";
   string result_headers;

   ResetLastError();
   int code = WebRequest("POST", url, headers, 10000, post, result, result_headers);
   if(code == -1)
   {
      out_err = "WebRequest failed err=" + IntegerToString(GetLastError())
              + " — Options > Expert Advisors > Allow WebRequest > " + InpLicenseServer;
      return false;
   }
   if(code != 200)
   {
      out_err = "HTTP " + IntegerToString(code);
      return false;
   }

   string respBody = CharArrayToString(result, 0, WHOLE_ARRAY, CP_UTF8);
   string okVal;
   if(!JsonField(respBody, "ok", okVal)) { out_err = "bad response"; return false; }
   if(okVal != "true")
   {
      string codeVal = "", msgVal = "";
      JsonField(respBody, "code", codeVal);
      JsonField(respBody, "message", msgVal);
      out_err = codeVal + ": " + msgVal;
      return false;
   }

   string expiresStr = "";
   if(JsonField(respBody, "expires_at", expiresStr) && expiresStr != "null" && expiresStr != "")
   {
      datetime parsed = ParseIso8601(expiresStr);
      if(parsed == 0) { out_err = "Server trả expires_at sai format: " + expiresStr; return false; }
      out_expires_at = parsed;
   }
   out_err = "";
   return true;
}


// ============================================================
// Live publisher helpers — build snapshot/positions/trades JSON
// ============================================================
string BuildSnapshotJson()
{
   double bal = AccountInfoDouble(ACCOUNT_BALANCE);
   double eq  = AccountInfoDouble(ACCOUNT_EQUITY);
   double mrg = AccountInfoDouble(ACCOUNT_MARGIN);
   double fmr = AccountInfoDouble(ACCOUNT_MARGIN_FREE);
   double prf = AccountInfoDouble(ACCOUNT_PROFIT);
   double crd = AccountInfoDouble(ACCOUNT_CREDIT);
   string cur = AccountInfoString(ACCOUNT_CURRENCY);
   long   lev = AccountInfoInteger(ACCOUNT_LEVERAGE);
   string srv = AccountInfoString(ACCOUNT_SERVER);
   ENUM_ACCOUNT_TRADE_MODE mode = (ENUM_ACCOUNT_TRADE_MODE)AccountInfoInteger(ACCOUNT_TRADE_MODE);
   string modeStr = (mode == ACCOUNT_TRADE_MODE_REAL) ? "real"
                  : (mode == ACCOUNT_TRADE_MODE_DEMO) ? "demo" : "contest";

   string s = "\"snapshot\":{";
   s += "\"balance\":"     + DoubleToString(bal, 2) + ",";
   s += "\"equity\":"      + DoubleToString(eq, 2) + ",";
   s += "\"margin\":"      + DoubleToString(mrg, 2) + ",";
   s += "\"free_margin\":" + DoubleToString(fmr, 2) + ",";
   s += "\"profit\":"      + DoubleToString(prf, 2) + ",";
   s += "\"credit\":"      + DoubleToString(crd, 2) + ",";
   s += "\"currency\":"    + JsonStr(cur) + ",";
   s += "\"leverage\":"    + IntegerToString(lev) + ",";
   s += "\"server\":"      + JsonStr(srv) + ",";
   s += "\"trade_mode\":"  + JsonStr(modeStr) + ",";
   s += "\"ea_version\":"  + JsonStr(InpLiveEaVersion);
   s += "}";
   return s;
}

string BuildPositionsJson()
{
   string s = "\"positions\":[";
   int total = PositionsTotal();
   bool first = true;
   for(int i = 0; i < total; i++)
   {
      ulong ticket = PositionGetTicket(i);
      if(ticket == 0 || !PositionSelectByTicket(ticket)) continue;
      string sym  = PositionGetString(POSITION_SYMBOL);
      long   ptyp = PositionGetInteger(POSITION_TYPE);
      double vol  = PositionGetDouble(POSITION_VOLUME);
      double op   = PositionGetDouble(POSITION_PRICE_OPEN);
      double cp   = PositionGetDouble(POSITION_PRICE_CURRENT);
      double psl  = PositionGetDouble(POSITION_SL);
      double ptp  = PositionGetDouble(POSITION_TP);
      double psw  = PositionGetDouble(POSITION_SWAP);
      double ppl  = PositionGetDouble(POSITION_PROFIT);
      datetime ot = (datetime)PositionGetInteger(POSITION_TIME);
      string cmt  = PositionGetString(POSITION_COMMENT);
      int digits  = (int)SymbolInfoInteger(sym, SYMBOL_DIGITS);

      if(!first) s += ",";
      first = false;
      s += "{";
      s += "\"ticket\":"        + IntegerToString((long)ticket) + ",";
      s += "\"symbol\":"        + JsonStr(sym) + ",";
      s += "\"type\":"          + JsonStr(ptyp == POSITION_TYPE_BUY ? "buy" : "sell") + ",";
      s += "\"volume\":"        + DoubleToString(vol, 2) + ",";
      s += "\"open_price\":"    + DoubleToString(op, digits) + ",";
      s += "\"current_price\":" + DoubleToString(cp, digits) + ",";
      s += "\"sl\":"            + DoubleToString(psl, digits) + ",";
      s += "\"tp\":"            + DoubleToString(ptp, digits) + ",";
      s += "\"swap\":"          + DoubleToString(psw, 2) + ",";
      s += "\"profit\":"        + DoubleToString(ppl, 2) + ",";
      s += "\"open_time\":"     + JsonStr(IsoTime(ot)) + ",";
      s += "\"comment\":"       + JsonStr(cmt);
      s += "}";
   }
   s += "]";
   return s;
}

string BuildTradesJson()
{
   // Đơn giản: 200 deal đóng gần nhất trong InpLiveHistoryDays ngày.
   string s = "\"trades\":[";
   datetime from_t = TimeCurrent() - InpLiveHistoryDays * 86400;
   datetime to_t   = TimeCurrent() + 86400;
   if(!HistorySelect(from_t, to_t)) { s += "]"; return s; }
   int total = HistoryDealsTotal();
   bool first = true;
   int sent = 0;
   for(int i = total - 1; i >= 0 && sent < 200; i--)
   {
      ulong deal = HistoryDealGetTicket(i);
      if(deal == 0) continue;
      ENUM_DEAL_ENTRY entry = (ENUM_DEAL_ENTRY)HistoryDealGetInteger(deal, DEAL_ENTRY);
      if(entry != DEAL_ENTRY_OUT) continue;
      ENUM_DEAL_TYPE dtype = (ENUM_DEAL_TYPE)HistoryDealGetInteger(deal, DEAL_TYPE);
      if(dtype != DEAL_TYPE_BUY && dtype != DEAL_TYPE_SELL) continue;

      ulong posId = HistoryDealGetInteger(deal, DEAL_POSITION_ID);
      double closePrice = HistoryDealGetDouble(deal, DEAL_PRICE);
      double vol = HistoryDealGetDouble(deal, DEAL_VOLUME);
      double profit = HistoryDealGetDouble(deal, DEAL_PROFIT);
      double commission = HistoryDealGetDouble(deal, DEAL_COMMISSION);
      double swap = HistoryDealGetDouble(deal, DEAL_SWAP);
      double sl = HistoryDealGetDouble(deal, DEAL_SL);
      double tp = HistoryDealGetDouble(deal, DEAL_TP);
      string sym = HistoryDealGetString(deal, DEAL_SYMBOL);
      datetime closeTm = (datetime)HistoryDealGetInteger(deal, DEAL_TIME);
      string cmt = HistoryDealGetString(deal, DEAL_COMMENT);

      // Tìm deal IN cùng position_id để có open_price/open_time
      double openPrice = 0; datetime openTm = 0;
      for(int j = 0; j < total; j++)
      {
         ulong d2 = HistoryDealGetTicket(j);
         if(d2 == 0) continue;
         if(HistoryDealGetInteger(d2, DEAL_POSITION_ID) != (long)posId) continue;
         if((ENUM_DEAL_ENTRY)HistoryDealGetInteger(d2, DEAL_ENTRY) != DEAL_ENTRY_IN) continue;
         openPrice = HistoryDealGetDouble(d2, DEAL_PRICE);
         openTm    = (datetime)HistoryDealGetInteger(d2, DEAL_TIME);
         break;
      }
      if(openTm == 0) openTm = closeTm;

      string typeStr = (dtype == DEAL_TYPE_BUY) ? "sell" : "buy";
      int digits = (int)SymbolInfoInteger(sym, SYMBOL_DIGITS);

      if(!first) s += ",";
      first = false;
      s += "{";
      s += "\"deal_id\":"     + JsonStr(IntegerToString((long)deal)) + ",";
      s += "\"symbol\":"      + JsonStr(sym) + ",";
      s += "\"type\":"        + JsonStr(typeStr) + ",";
      s += "\"volume\":"      + DoubleToString(vol, 2) + ",";
      s += "\"open_price\":"  + DoubleToString(openPrice, digits) + ",";
      s += "\"close_price\":" + DoubleToString(closePrice, digits) + ",";
      s += "\"sl\":"          + DoubleToString(sl, digits) + ",";
      s += "\"tp\":"          + DoubleToString(tp, digits) + ",";
      s += "\"open_time\":"   + JsonStr(IsoTime(openTm)) + ",";
      s += "\"close_time\":"  + JsonStr(IsoTime(closeTm)) + ",";
      s += "\"profit\":"      + DoubleToString(profit, 2) + ",";
      s += "\"commission\":"  + DoubleToString(commission, 2) + ",";
      s += "\"swap\":"        + DoubleToString(swap, 2) + ",";
      s += "\"comment\":"     + JsonStr(cmt);
      s += "}";
      sent++;
   }
   s += "]";
   return s;
}

bool DoLivePush(string &out_err)
{
   string body = "{" + BuildSnapshotJson() + "," + BuildPositionsJson() + "," + BuildTradesJson() + "}";
   long ts = (long)TimeGMT();
   string bodyHash = Sha256Hex(body);
   string canonical = InpLiveSlug + "|" + IntegerToString(ts) + "|" + bodyHash;
   string sig = Hmac256Hex(InpLiveSecret, canonical);

   char post[], result[];
   int bodyLen = StringLen(body);
   ArrayResize(post, bodyLen);
   StringToCharArray(body, post, 0, bodyLen);

   string headers = "Content-Type: application/json\r\n";
   headers += "X-Live-Timestamp: " + IntegerToString(ts) + "\r\n";
   headers += "X-Live-Signature: " + sig + "\r\n";
   string url = InpLiveServer + "/api/live/" + InpLiveSlug + "/ingest";
   string resp_headers = "";
   ResetLastError();
   int code = WebRequest("POST", url, headers, 5000, post, result, resp_headers);
   if(code == -1)
   {
      out_err = StringFormat("WebRequest err=%d (allow %s trong Options > Expert Advisors)",
                             GetLastError(), InpLiveServer);
      return false;
   }
   if(code < 200 || code >= 300)
   {
      out_err = StringFormat("HTTP %d: %s", code, CharArrayToString(result));
      return false;
   }
   return true;
}


// ============================================================
// Runtime state
// ============================================================
datetime g_expiresAt     = 0;     // 0 = vĩnh viễn
datetime g_lastSeenTime  = 0;     // monotonic clock — phát hiện rollback
datetime g_lastPersistAt = 0;
bool     g_licenseOk     = false;
string   g_rollbackVar   = "";
bool     g_liveEnabled   = false;
datetime g_lastLivePush  = 0;

const int ROLLBACK_TOLERANCE_SEC = 60;    // tolerance cho NTP sync nhẹ
const int PERSIST_INTERVAL_SEC   = 300;   // ghi GlobalVariable mỗi 5 phút


// ============================================================
// OnInit — verify license + init publisher
// ============================================================
int OnInit()
{
   string err;
   if(!LicenseVerify(InpLicenseKey, err, g_expiresAt))
   {
      Alert("License invalid: ", err);
      return INIT_FAILED;
   }

   datetime now = TimeGMT();

   // Anti rollback CROSS-SESSION — persist last seen time qua MT5 GlobalVar
   g_rollbackVar = "easeller_lastseen_" + InpLicenseKey;
   datetime persisted = (datetime)GlobalVariableGet(g_rollbackVar);
   if(persisted > 0 && now < persisted - ROLLBACK_TOLERANCE_SEC)
   {
      Alert("Phát hiện đồng hồ máy bị xoay về trước (last seen: ",
            TimeToString(persisted, TIME_DATE|TIME_SECONDS),
            ", now: ", TimeToString(now, TIME_DATE|TIME_SECONDS),
            "). EA không khởi động vì lý do bảo mật.");
      return INIT_FAILED;
   }
   g_lastSeenTime  = (datetime)MathMax((double)now, (double)persisted);
   g_lastPersistAt = now;
   GlobalVariableSet(g_rollbackVar, (double)g_lastSeenTime);
   g_licenseOk = true;

   if(g_expiresAt == 0)
      Print("✓ License OK (vĩnh viễn)");
   else
      Print("✓ License OK, hết hạn ", TimeToString(g_expiresAt, TIME_DATE),
            " (còn ", (int)((g_expiresAt - now) / 86400), " ngày)");

   // Live publisher — chỉ bật nếu đủ server + slug + secret 64-hex
   if(StringLen(InpLiveServer) > 0 && StringLen(InpLiveSlug) >= 2 && StringLen(InpLiveSecret) == 64)
   {
      g_liveEnabled = true;
      EventSetTimer(MathMax(1, InpLivePushSec));
      PrintFormat("✓ Live publisher BẬT — slug=%s, push mỗi %ds", InpLiveSlug, InpLivePushSec);
   }
   else
   {
      g_liveEnabled = false;
      Print("ℹ Live publisher TẮT (Live Server/Slug/Secret rỗng hoặc secret không đủ 64 ký tự)");
   }

   return INIT_SUCCEEDED;
}


// ============================================================
// OnTimer — push live snapshot
// ============================================================
void OnTimer()
{
   if(!g_liveEnabled || !g_licenseOk) return;
   string err = "";
   if(DoLivePush(err))
   {
      g_lastLivePush = TimeCurrent();
   }
   else
   {
      PrintFormat("[Live] push failed: %s", err);
   }
}


// ============================================================
// OnDeinit — cleanup
// ============================================================
void OnDeinit(const int reason)
{
   EventKillTimer();
   if(g_rollbackVar != "" && g_lastSeenTime > 0)
   {
      GlobalVariableSet(g_rollbackVar, (double)g_lastSeenTime);
   }
}


// ============================================================
// OnTick — license guard + trading logic
// ============================================================
void OnTick()
{
   if(!g_licenseOk) return;
   datetime now = TimeGMT();

   // Anti rollback IN-SESSION
   if(now < g_lastSeenTime - ROLLBACK_TOLERANCE_SEC)
   {
      Alert("Phát hiện đồng hồ máy bị xoay về trước. EA dừng.");
      g_licenseOk = false;
      ExpertRemove();
      return;
   }
   if(now > g_lastSeenTime) g_lastSeenTime = now;
   if(now - g_lastPersistAt >= PERSIST_INTERVAL_SEC)
   {
      GlobalVariableSet(g_rollbackVar, (double)g_lastSeenTime);
      g_lastPersistAt = now;
   }

   // Expiry check LOCAL (không gọi server runtime — tránh server lỗi → EA dừng giữa lệnh)
   if(g_expiresAt > 0 && now >= g_expiresAt)
   {
      Alert("License đã hết hạn ", TimeToString(g_expiresAt, TIME_DATE),
            ". EA dừng. Vui lòng gia hạn và restart EA.");
      g_licenseOk = false;
      ExpertRemove();
      return;
   }

   // ============================================================
   //  TRADING LOGIC STUB — viết chiến lược của bạn ở đây
   //  Có thể dùng InpLotSize, InpMagicNumber.
   // ============================================================
   // Ví dụ kiểm tra position của EA này (lọc theo magic):
   //   int total = PositionsTotal();
   //   for(int i = 0; i < total; i++) {
   //     ulong t = PositionGetTicket(i);
   //     if(PositionSelectByTicket(t) && PositionGetInteger(POSITION_MAGIC) == InpMagicNumber) {
   //       ...
   //     }
   //   }
}
