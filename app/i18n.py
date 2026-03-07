# ...new file...
translations = {
    "en": {
        "name": "SafePlay AI",
        "stage_LOW": "LOW",
        "stage_TRUST_BUILDING": "TRUST BUILDING",
        "stage_INFO_GATHERING": "INFO GATHERING",
        "stage_ISOLATION": "ISOLATION",
        "stage_GROOMING": "GROOMING",
        "version": "1.0.0",
        "demo_ui": "Chat Demo",
        "health_ok": "ok",
    },
    "de": {
        "name": "SafePlay AI",
        "stage_LOW": "NIEDRIG",
        "stage_TRUST_BUILDING": "VERTRAUENSAUFBAU",
        "stage_INFO_GATHERING": "INFORMATIONSERHEBUNG",
        "stage_ISOLATION": "ISOLIERUNG",
        "stage_GROOMING": "GROOMING",
        "version": "1.0.0",
        "demo_ui": "Chat Demo",
        "health_ok": "ok",
    },
}

def parse_accept_language(header: str | None) -> str:
    if not header:
        return "en"
    part = header.split(",")[0].strip().lower()
    lang = part.split("-")[0]
    return lang if lang in translations else "en"

def t(lang: str, key: str) -> str:
    return translations.get(lang, translations["en"]).get(key, translations["en"].get(key, key))
