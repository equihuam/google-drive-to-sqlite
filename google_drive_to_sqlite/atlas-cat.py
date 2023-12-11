import click
import httpx
# import itertools
import json
import pathlib
import sqlite_utils
import sys
# import textwrap
import urllib.parse
from GD_upload_update_file import upload_db_file
from gd2sqlite import stream_indented_json
from atlas_utils import (
    APIClient,
    get_file,
    files_in_folder_recursive,
    paginate_files,
    save_files_and_folders,
)

FORMAT_SHORTCUTS = {
    "html": "text/html",
    "txt": "text/plain",
    "rtf": "application/rtf",
    "pdf": "application/pdf",
    "doc": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "zip": "application/zip",
    "epub": "application/epub+zip",
    "xls": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "csv": "text/csv",
    "tsv": "text/tab-separated-values",
    "ppt": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
    "jpeg": "image/jpeg",
    "png": "image/png",
    "svg": "image/svg+xml",
}

# .ext defaults to the bit after the / - e.g. "application/pdf" becomes "pdf",
# unless there is an explicit override here:
FILE_EXTENSIONS = {
    "image/svg+xml": "svg",
    "application/epub+zip": "epub",
    "text/plain": "txt",
    "text/tab-separated-values": "tsv",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": "doc",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": "xls",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": "ppt",
}

DEFAULT_FIELDS = [
    "kind",
    "id",
    "name",
    "mimeType",
    "starred",
    "trashed",
    "explicitlyTrashed",
    "parents",
    "spaces",
    "version",
    "webViewLink",
    "iconLink",
    "hasThumbnail",
    "thumbnailVersion",
    "viewedByMe",
    "createdTime",
    "modifiedTime",
    "modifiedByMe",
    "owners",
    "lastModifyingUser",
    "shared",
    "ownedByMe",
    "viewersCanCopyContent",
    "copyRequiresWriterPermission",
    "writersCanShare",
    "folderColorRgb",
    "quotaBytesUsed",
    "isAppAuthorized",
    "linkShareMetadata"]


def start_auth_url(google_client_id, scope):
    return "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(
        {
            "access_type": "offline",
            "client_id": google_client_id,
            "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
            "response_type": "code",
            "scope": scope,
        }
    )


def load_tokens(authenticated):
    try:
        token_info = json.load(open(authenticated))["google-drive-to-sqlite"]
    except (KeyError, FileNotFoundError):
        raise click.ClickException("Could not find google-drive-to-sqlite in authenticated.json")
    return {
        "refresh_token": token_info["refresh_token"],
        "client_id": token_info.get("google_client_id", GOOGLE_CLIENT_ID),
        "client_secret": token_info.get("google_client_secret", GOOGLE_CLIENT_SECRET),
    }


def auth(authenticated, google_client_id, google_client_secret, scope):
    """Authenticate user and save credentials"""
    if google_client_id is None:
        google_client_id = GOOGLE_CLIENT_ID
    if google_client_secret is None:
        google_client_secret = GOOGLE_CLIENT_SECRET
    if scope is None:
        scope = DEFAULT_SCOPE
    click.echo("Visit the following URL to authenticate with Google Drive")
    click.echo("")
    click.echo(start_auth_url(google_client_id, scope))
    click.echo("")
    click.echo("Then return here and paste in the resulting code:")
    copied_code = click.prompt("Paste code here", hide_input=True)
    response = httpx.post("https://www.googleapis.com/oauth2/v4/token",
                          data={"code": copied_code,
                                "client_id": google_client_id,
                                "client_secret": google_client_secret,
                                "redirect_uri": "urn:ietf:wg:oauth:2.0:oob",
                                "grant_type": "authorization_code"}
                          )
    tokens = response.json()
    if "error" in tokens:
        message = "{error}: {error_description}".format(**tokens)
        raise click.ClickException(message)
    if "refresh_token" not in tokens:
        raise click.ClickException("No refresh_token in response")
    # Read existing file and add refresh_token to it
    try:
        auth_data = json.load(open(authenticated))
    except (ValueError, FileNotFoundError):
        auth_data = {}
    info = {"refresh_token": tokens["refresh_token"]}
    if google_client_id != GOOGLE_CLIENT_ID:
        info["google_client_id"] = google_client_id
    if google_client_secret != GOOGLE_CLIENT_SECRET:
        info["google_client_secret"] = google_client_secret
    if scope != DEFAULT_SCOPE:
        info["scope"] = scope
    auth_data["google-drive-to-sqlite"] = info
    with open(authenticated, "w") as fp:
        fp.write(json.dumps(auth_data, indent=4))
    # chmod 600 to avoid other users on the shared machine reading it
    pathlib.Path(authenticated).chmod(0o600)


def revoke(authenticated):
    """Revoke the token stored in authenticated.json"""
    tokens = load_tokens(authenticated)
    response = httpx.get(
        "https://accounts.google.com/o/oauth2/revoke",
        params={
            "token": tokens["refresh_token"],
        },
    )
    if "error" in response.json():
        raise click.ClickException(response.json()["error"])


def get(url, authenticated, paginate, nl, stop_after, verbose):
    """Make an authenticated HTTP GET to the specified URL"""
    if not url.startswith("https://www.googleapis.com/"):
        if url.startswith("/"):
            url = "https://www.googleapis.com" + url
        else:
            raise click.ClickException(
                "url must start with / or https://www.googleapis.com/"
            )

    kwargs = load_tokens(authenticated)
    if verbose:
        kwargs["logger"] = lambda s: click.echo(s, err=True)
    client = APIClient(**kwargs)

    if not paginate:
        response = client.get(url)
        if verbose:
            click.echo(
                "{}, headers: {}".format(response.status_code, repr(response.headers))
            )
        if response.status_code != 200:
            raise click.ClickException(
                "{}: {}\n\n{}".format(response.url, response.status_code, response.text)
            )
        if "json" in response.headers.get("content-type", ""):
            click.echo(json.dumps(response.json(), indent=4))
        else:
            click.echo(response.text)

    else:
        def paginate_all():
            i = 0
            next_page_token = None
            while True:
                params = {}
                if next_page_token is not None:
                    params["pageToken"] = next_page_token
                response_i = client.get(
                    url,
                    params=params,
                )
                data = response_i.json()
                if response_i.status_code != 200:
                    raise click.ClickException(json.dumps(data, indent=4))
                # Paginate using the specified key and nextPageToken
                if paginate not in data:
                    raise click.ClickException(
                        "paginate key {} not found in {}".format(
                            repr(paginate), repr(list(data.keys()))
                        )
                    )
                for item_1 in data[paginate]:
                    yield item_1
                    i += 1
                    if stop_after is not None and i >= stop_after:
                        return

                next_page_token = data.get("nextPageToken")
                if not next_page_token:
                    break

        if nl:
            for item in paginate_all():
                click.echo(json.dumps(item))
        else:
            for line in stream_indented_json(paginate_all()):
                click.echo(line)


def files(database,
          authenticated,
          folder,
          q,
          full_text,
          starred,
          trashed,
          shared_with_me,
          apps,
          docs,
          sheets,
          presentations,
          drawings,
          json_,
          nl,
          stop_after,
          import_json,
          import_nl,
          verbose):
    """
    Retrieve metadata for files in Google Drive, and write to a SQLite database
    or output as JSON.

        google-drive-to-sqlite files files.db

    Use --json to output JSON, --nl for newline-delimited JSON:

        google-drive-to-sqlite files files.db --json

    Use a folder ID to recursively fetch every file in that folder and its
    sub-folders:

        google-drive-to-sqlite files files.db --folder 1E6Zg2X2bjjtPzVfX8YqdXZDCoB3AVA7i

    Fetch files you have starred:

        google-drive-to-sqlite files starred.db --starred
    """
    if not database and not json_ and not nl:
        raise click.ClickException("Must either provide database or use --json or --nl")
    q_bits = []
    if q:
        q_bits.append(q)
    if full_text:
        q_bits.append("fullText contains '{}'".format(full_text.replace("'", "")))
    if starred:
        q_bits.append("starred = true")
    if trashed:
        q_bits.append("trashed = true")
    if shared_with_me:
        q_bits.append("sharedWithMe = true")

    mime_types = []
    if apps:
        docs = True
        sheets = True
        presentations = True
        drawings = True
    if docs:
        mime_types.append("application/vnd.google-apps.document")
    if sheets:
        mime_types.append("application/vnd.google-apps.spreadsheet")
    if presentations:
        mime_types.append("application/vnd.google-apps.presentation")
    if drawings:
        mime_types.append("application/vnd.google-apps.drawing")
    if mime_types:
        q_bits.append(
            "({})".format(
                " or ".join(
                    "mimeType = '{}'".format(mime_type) for mime_type in mime_types
                )
            )
        )

    q = " and ".join(q_bits)

    if q and verbose:
        click.echo("?q= query: {}".format(q), err=True)

    client = None
    if not (import_json or import_nl):
        kwargs = load_tokens(authenticated)
        if verbose:
            kwargs["logger"] = lambda s: click.echo(s, err=True)
        client = APIClient(**kwargs)

    if import_json or import_nl:
        if "-" in (import_json, import_nl):
            fp = sys.stdin
        else:
            fp = open(import_json or import_nl)
        if import_json:
            all_1 = json.load(fp)
        else:

            def _nl():
                for line_f in fp:
                    line_f = line_f.strip()
                    if line_f:
                        yield json.loads(line_f)

            all_1 = _nl()
    else:
        if folder:
            all_in_folder = files_in_folder_recursive(
                client, folder, fields=DEFAULT_FIELDS)

            # Fetch details of that folder first
            folder_details = get_file(client, folder, fields=DEFAULT_FIELDS)

            def folder_details_then_all():
                yield folder_details
                yield from all_in_folder

            all_1 = folder_details_then_all()
        else:
            all_1 = paginate_files(client, q=q, fields=DEFAULT_FIELDS)

    if stop_after:
        prev_all = all_1

        def stop_after_all():
            i = 0
            for file_p in prev_all:
                yield file_p
                i += 1
                if i >= stop_after:
                    break

        all_1 = stop_after_all()

    if nl:
        for file in all_1:
            click.echo(json.dumps(file))
        return
    if json_:
        for line in stream_indented_json(all_1):
            click.echo(line)
        return

    db = sqlite_utils.Database(database)
    save_files_and_folders(db, all_1)


if __name__ == '__main__':

    # Confidential information
    with open("privado/credenciales.json") as f:
        credentials = json.load(f)
    credentials = {k: v for k, v in credentials["installed"].items()}
    with open("privado/directorio_a_procesar.json") as f:
        credentials.update(json.load(f))

    DEFAULT_SCOPE = "https://www.googleapis.com/auth/drive.readonly"
    GOOGLE_CLIENT_ID = credentials["client_id"]
    GOOGLE_CLIENT_SECRET = credentials["client_secret"]
    TARGET_FOLDER = credentials["target_folder"]
    CONTROL_FOLDER = credentials["control_folder"]

    #auth("authenticated.json", GOOGLE_CLIENT_ID, GOOGLE_CLIENT_SECRET, DEFAULT_SCOPE)

    # If all is ready, this function scans Google Drive Folder and updates de SQLite file
    files("atlas-y-cat.db", authenticated="authenticated.json", folder=TARGET_FOLDER,
          q="",
          full_text="",
          starred=False,
          trashed=False,
          shared_with_me=False,
          apps=True,
          docs=False,
          sheets=False,
          presentations=False,
          drawings=False,
          json_="",
          nl="",
          stop_after=None,
          import_json=False,
          import_nl=False,
          verbose=False)

    upload_db_file(CONTROL_FOLDER)
