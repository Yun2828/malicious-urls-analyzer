SUSPICIOUS_WORD_EXPLANATIONS = {
    "login": "The URL contains 'login', which can be normal but is also commonly used in phishing pages that imitate sign-in forms.",
    "verify": "The URL contains 'verify', which is often used in phishing links to pressure users into confirming an account.",
    "update": "The URL contains 'update', which attackers may use to make a link look like an urgent account or security update.",
    "secure": "The URL contains 'secure', which can be used to make a suspicious link appear trustworthy.",
    "account": "The URL contains 'account', which is commonly used in phishing pages targeting user accounts.",
    "password": "The URL contains 'password', which can indicate a page related to credential collection.",
    "free": "The URL contains 'free', which is often used in scam or lure-based links.",
    "download": "The URL contains 'download', which may indicate a file download and can be risky when combined with unknown domains or executable files.",
    "gift": "The URL contains 'gift', which is often used in scam or reward-based phishing links.",
    "winner": "The URL contains 'winner', which is commonly used in prize scam links.",
    "confirm": "The URL contains 'confirm', which attackers may use to make users confirm fake account or payment activity.",
    "token": "The URL contains 'token', which can indicate authentication or session-related data.",
    "session": "The URL contains 'session', which can indicate session-related tracking or authentication data.",
    "bank": "The URL contains 'bank', which may indicate financial targeting and should be treated carefully.",
}

QUERY_TOKEN_EXPLANATIONS = {
    "user=": "Query string includes 'user=', which may pass a username or user identifier.",
    "token=": "Query string includes 'token=', which may pass authentication, reset, or tracking tokens.",
    "session=": "Query string includes 'session=', which may pass a session identifier.",
    "email=": "Query string includes 'email=', which may expose or target a specific email address.",
}

ENCODING_EXPLANATIONS = {
    "%20": "Contains '%20', which represents a space. Encoded spaces are normal in some URLs, but attackers can use encoding to hide or disguise URL text.",
    "%40": "Contains '%40', which represents '@'. Encoded email symbols can be used in targeted or confusing links.",
}

FILE_EXTENSION_EXPLANATIONS = {
    ".exe": "Path ends with '.exe', which is a Windows executable file and can carry malware.",
    ".zip": "Path ends with '.zip', which is an archive file. Archives can hide malware or unwanted files.",
    ".scr": "Path ends with '.scr', which is a Windows screensaver executable and can be abused for malware.",
    ".dll": "Path ends with '.dll', which is a Windows library file and can be suspicious when downloaded directly.",
}