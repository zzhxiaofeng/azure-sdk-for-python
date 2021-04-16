# --------------------------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for license information.
# --------------------------------------------------------------------------------------------
from azure.storage.blob import AzureBlobStorage
from azure.storage.blob.rest.blob import build_download_request

def test_stream_download_blob():
    client = AzureBlobStorage(url="hello")

    request = build_download_request()
    total_blob = None
    with client.send_request(request, stream_response=True) as response:
        for data in response.iter_raw():
            total_blob += data
