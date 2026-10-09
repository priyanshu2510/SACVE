import certifi


def ca_bundle_path() -> str:
    return certifi.where()
