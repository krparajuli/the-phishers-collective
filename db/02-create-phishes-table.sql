CREATE TABLE phishes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,

   phishing_text TEXT NOT NULL,
   extracted_url TEXT DEFAULT "Unextracted",
   received_via TEXT NOT NULL,
   device TEXT DEFAULT "Unspecified",
   device_brand TEXT DEFAULT "Unspecified",

    user_agent TEXT DEFAULT "N/A",
    all_http_headers TEXT DEFAULT "N/A",
    cf_request_headers TEXT DEFAULT "N/A",
    ip TEXT DEFAULT "N/A", --- Collected for value resolution
    created_at TEXT        --- IP and time based resolution
);
