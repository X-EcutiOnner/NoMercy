import os
import time
import requests
import urllib.parse
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.util.retry import Retry
from zipfile import ZipFile


import sys
from io import BytesIO
import json
import shutil

import logging
import argparse

import tempfile

import asyncio
from aiohttp import ClientSession
from aiohttp.client_exceptions import ClientConnectorError


logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger(__name__)

TENANT_ID = os.environ.get('TENANT_ID')
CLIENT_ID = os.environ.get('CLIENT_ID')
CLIENT_SECRET = os.environ.get('CLIENT_SECRET')
PRODUCT_NAME = os.environ.get('PRODUCT_NAME')
SIGNATURES = os.environ.get('SIGNATURES')
BIN_PATH_IN = os.environ.get('BIN_PATH_IN')
BIN_PATH_OUT = os.environ.get('BIN_PATH_OUT')
USE_OUTPUT = bool(BIN_PATH_OUT)

"""
tenant-id:  
client-id: 
secret-id: 
product-id: 14494271338463745
signatures: '["WINDOWS_v100_TH2_FULL", "WINDOWS_v100_X64_TH2_FULL", "WINDOWS_v100_RS1_FULL"]'
bin-path-in: ./yourpackage.cab
bin-path-out: .
"""

ERRORS = {
  'INVALID_CREDENTIALS': 'An invalid credentials specified',
  'SUBMISSION_FAILED': 'A submission failed',
  'SUBMISSION_COMMIT_FAILED': 'A submission commit failed',
  'SUBMISSION_QUERY_FAILED': 'A submission query failed',
  'SUBMISSION_UPLOAD_FAILED': 'A submission file upload failed',
  'SUBMISSION_CREATE_FAILED': 'A submission creation failed',
  'SUBMISSION_PRODUCT_CREATE_FAILED': 'A submission product creation failed',
}


class Session:
    def __init__(self, tenantId, clientId, clientSecret):
        self.tenantId = tenantId
        self.clientId = clientId
        self.clientSecret = clientSecret
        self.tokenType = None
        self.token = None
        self.auth = None
        self.product = None
        self.submission = None
        self.status = None

    async def init(self):
        payload = {
            'grant_type': 'client_credentials',
            'client_id': self.clientId,
            'client_secret': self.clientSecret,
            'resource': 'https://manage.devcenter.microsoft.com'
        }

        url = f'https://login.microsoftonline.com/{self.tenantId}/oauth2/token'
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}

        async with ClientSession() as session:
            retry = Retry(total=10, backoff_factor=5, status_forcelist=[500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            async with session.post(url, headers=headers, data=payload) as response:
                if response.status == 200:
                    data = await response.json()
                    self.tokenType = data['token_type']
                    self.token = data['access_token']
                    self.auth = f'{self.tokenType} {self.token}'

                    log.debug('Authentication succeeded')

    async def newProduct(self, productName):
        payload = {
            'productName': productName,
            'testHarness': 'attestation',
            'deviceMetadataIds': [],
            'deviceType': 'internalExternal',
            'isTestSign': False,
            'isFlightSign': False,
            'marketingNames': [],
            'selectedProductTypes': {},
            'requestedSignatures': json.loads(SIGNATURES),
            'additionalAttributes': {}
        }

        url = 'https://manage.devcenter.microsoft.com/v2.0/my/hardware/products/'
        headers = {'Authorization': self.auth}

        async with ClientSession() as session:
            retry = Retry(total=10, backoff_factor=5, status_forcelist=[500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 200:
                    self.product = await response.json()

    async def newSubmission(self, productId, productName, productType='initial'):
        payload = {
            'name': productName,
            'type': productType
        }

        url = f'https://manage.devcenter.microsoft.com/v2.0/my/hardware/products/{productId}/submissions'
        headers = {'Authorization': self.auth}

        async with ClientSession() as session:
            retry = Retry(total=10, backoff_factor=5, status_forcelist=[500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            async with session.post(url, headers=headers, json=payload) as response:
                if response.status == 200:
                    self.submission = await response.json()

    async def uploadFile(self, url, path):
        with open(path, 'rb') as file:
            data = file.read()

        headers = {
            'x-ms-blob-type': 'BlockBlob',
            'Content-Length': str(len(data))
        }

        async with ClientSession() as session:
            retry = Retry(total=10, backoff_factor=5, status_forcelist=[500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            async with session.put(url, headers=headers, data=data) as response:
                if response.status == 201:
                    return True
                else:
                    raise Exception(ERRORS['SUBMISSION_UPLOAD_FAILED'])

    async def commitSubmission(self, productId, submissionId):
        url = f'https://manage.devcenter.microsoft.com/v2.0/my/hardware/products/{productId}/submissions/{submissionId}/commit'
        headers = {
            'Authorization': self.auth,
            'Content-Type': 'application/json',
            'Content-Length': '0'
        }

        async with ClientSession() as session:
            retry = Retry(total=10, backoff_factor=5, status_forcelist=[500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            async with session.post(url, headers=headers) as response:
                return True

    async def querySubmission(self, productId, submissionId):
        url = f'https://manage.devcenter.microsoft.com/v2.0/my/hardware/products/{productId}/submissions/{submissionId}'
        headers = {'Authorization': self.auth}

        async with ClientSession() as session:
            retry = Retry(total=10, backoff_factor=5, status_forcelist=[500, 502, 503, 504])
            adapter = HTTPAdapter(max_retries=retry)
            session.mount('http://', adapter)
            session.mount('https://', adapter)

            async with session.get(url, headers=headers) as response:
                if response.status == 200:
                    self.status = await response.json()

async def downloadFileFromUrl(url, file):
    async with ClientSession() as session:
        async with session.get(url) as response:
            if response.status == 200:
                data = await response.read()
                with open(file, 'wb') as f:
                    f.write(data)

async def main():
    session = Session(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
    await session.init()

    print('create new product...')
    await session.newProduct(PRODUCT_NAME)
    productIdStr = session.product['links'][0]['href'].split('/')[-1]
    print(f'created product id: {productIdStr}')

    print('create new submission...')
    await session.newSubmission(productIdStr, PRODUCT_NAME)
    submissionIdStr = session.submission['links'][0]['href'].split('/')[-1]
    print(f'created submission id: {submissionIdStr}')

    uploadUrl = session.submission['downloads']['items'][0]['url']
    print(f'upload url: {uploadUrl}')

    print('upload to blob...')
    uploaded = await session.uploadFile(uploadUrl, BIN_PATH_IN)
    print(f'the file has been uploaded to blob ({uploaded})')

    print('commit submission...')
    commit_retry_count = 0
    while True:
        try:
            commited = await session.commitSubmission(productIdStr, submissionIdStr)
            if commited:
                break
        except Exception as err:
            print(f'{ERRORS["SUBMISSION_COMMIT_FAILED"]}: {err}')
            if commit_retry_count < 10:
                commit_retry_count += 1
                continue
            else:
                raise Exception(ERRORS["SUBMISSION_COMMIT_FAILED"])

    print('submission has been committed')
    print('wait for the submission to complete')

    previousStep = ''
    while True:
        session = Session(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
        await session.init()

        await session.querySubmission(productIdStr, submissionIdStr)
        step = session.status['workflowStatus']['currentStep']
        state = session.status['workflowStatus']['state']

        if previousStep:
            if previousStep != step:
                print(f'step has been changed to: {step}')
                previousStep = step
        else:
            print(f'current step: {step}')
            previousStep = step

        if state == 'completed':
            print('the submission has been completed successfully')

            if USE_OUTPUT:
                foundSignedPackage = False
                while not foundSignedPackage:
                    items = session.status['downloads']['items']
                    for v in items:
                        if v['type'] == 'signedPackage':
                            print(f'signed package download url: {v["url"]}')
                            zipFileName = os.path.join(BIN_PATH_OUT, 'signed.zip')
                            await downloadFileFromUrl(v['url'], zipFileName)
                            with zipfile.ZipFile(zipFileName, 'r') as zip_ref:
                                zip_ref.extractall(BIN_PATH_OUT)
                            foundSignedPackage = True
                            break
                    if foundSignedPackage:
                        break
                    session = Session(TENANT_ID, CLIENT_ID, CLIENT_SECRET)
                    await session.init()
                    await session.querySubmission(productIdStr, submissionIdStr)
                    await asyncio.sleep(5)

            break
        elif state == 'failed':
            raise Exception(ERRORS["SUBMISSION_FAILED"])
        
        await asyncio.sleep(5)

    print('done')

asyncio.run(main())
