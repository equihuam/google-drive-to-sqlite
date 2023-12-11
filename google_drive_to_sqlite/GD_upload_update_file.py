
"""
Needs the following libraries for google drive interaction:
google-api-python-client google-auth-httplib2 google-auth-oauthlib
"""
import json
import os.path
from google.auth.transport.requests import Request
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from googleapiclient.http import MediaFileUpload

def upload_db_file(control_folder):
  """
  Insert new file.
  Returns : Id's of the file uploaded

  Load pre-authorized user credentials from the environment.
  """
  SCOPE = "https://www.googleapis.com/auth/drive.file"
  creds = None
  # The file credenciales.json stores the user's access and refresh tokens, and is
  # created automatically when the authorization flow completes for the first
  # time.
  if os.path.exists("token.json"):
      creds = Credentials.from_authorized_user_file("token.json", SCOPE)
  # If there are no (valid) credentials available, let the user log in.
  if not creds or not creds.valid:
      if creds and creds.expired and creds.refresh_token:
          creds.refresh(Request())
      else:
          flow = InstalledAppFlow.from_client_secrets_file(
              "privado/credenciales.json", SCOPE
          )
          creds = flow.run_local_server(port=0)
      # Save the credentials for the next run
      with open("token.json", "w") as token:
          token.write(creds.to_json())

  try:
    # create drive api client
    service = build("drive", "v3", credentials=creds)

    file_metadata = {"name": "atlas-y-cat.db", 'parents': [control_folder]}
    media = MediaFileUpload("atlas-y-cat.db", mimetype="application/vnd.sqlite3")
    # pylint: disable=maybe-no-member
    # file = (
    #     service.files().create(body=file_metadata,
    #                            media_body=media,
    #                            fields="id").execute()
    #        )
    #print(f'File ID: {file.get("id")}')
        #Update service.files().update 19YDUdrQWShywULwhw_p-iM6kLGtbubbG
    service.files().update(fileId="19YDUdrQWShywULwhw_p-iM6kLGtbubbG",
                           media_body=media).execute()

  except HttpError as error:
    print(f"An error occurred: {error}")
    #file = None

  #return file.get("id")

if __name__ == "__main__":

    # Confidential information
    with open("privado/credenciales.json") as f:
        credentials = json.load(f)
        credentials = {k: v for k, v in credentials["installed"].items()}

    with open("privado/directorio_a_procesar.json") as f:
        credentials.update(json.load(f))

    GOOGLE_CLIENT_ID = credentials["client_id"]
    GOOGLE_CLIENT_SECRET = credentials["client_secret"]
    TARGET_FOLDER = credentials["target_folder"]
    CONTROL_FOLDER = credentials["control_folder"]

    upload_db_file(CONTROL_FOLDER)