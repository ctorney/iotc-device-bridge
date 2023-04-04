/*!
 * Copyright (c) Microsoft Corporation. All rights reserved.
 * Licensed under the MIT License.
 */

const crypto = require('crypto');
const fetch = require('node-fetch');
const Device = require('azure-iot-device');
const DeviceTransport = require('azure-iot-device-http');

const StatusError = require('../error').StatusError;

const registrationHost = 'global.azure-devices-provisioning.net';
const registrationSasTtl = 3600; // 1 hour
const registrationApiVersion = `2019-03-31`;
const registrationStatusQueryAttempts = 10;
const registrationStatusQueryTimeout = 2000;
const minDeviceRegistrationTimeout = 60*1000; // 1 minute

const deviceCache = {};

/**
 * Forwards external telemetry messages for IoT Central devices.
 * @param {{ idScope: string, primaryKeyUrl: string, log: Function, getSecret: (context: Object, secretUrl: string) => string }} context 
 * @param {{ deviceId: string }} device 
 * @param {{ [field: string]: number }} measurements 
 */
module.exports = async function (context, loraMessage) {
    if (!loraMessage.endDevice) {
        throw new StatusError('endDevice object missing');
    }
    if (!loraMessage.endDevice.devEui || !/^[A-Za-z0-9]{16}$/.test(loraMessage.endDevice.devEui)) {
        throw new StatusError('Invalid format: devEui must be a 16 digit hex string.', 400);
    }

    if (!loraMessage.payload) {
        throw new StatusError('Invalid format: invalid payload.', 400);
    }

    const date = new Date(loraMessage.recvTime);

    const client = Device.Client.fromConnectionString(await getDeviceConnectionString(context, loraMessage.endDevice), DeviceTransport.Http);

    try {

        const measurements = decodeUplink(loraMessage)
        context.log("payload decoded: ", measurements);

        const message = new Device.Message(JSON.stringify(measurements));
        message.contentEncoding = 'utf-8';
        message.contentType = 'application/json';

        message.properties.add('iothub-creation-time-utc', date.toString());

        await client.open();
        context.log('[HTTP] Sending telemetry for device',  loraMessage.endDevice.devEui);
        await client.sendEvent(message);
        await client.close();
    } catch (e) {
        // If the device was deleted, we remove its cached connection string
        if (e.name === 'DeviceNotFoundError' && deviceCache[loraMessage.endDevice.devEui]) {
            delete deviceCache[loraMessage.endDevice.devEui].connectionString;
        }

        throw new Error(`Unable to send telemetry for device ${loraMessage.endDevice.devEui}: ${e.message}`);
    }
};


async function getDeviceConnectionString(context, device) {
    const deviceId = device.devEui;

    if (deviceCache[deviceId] && deviceCache[deviceId].connectionString) {
        return deviceCache[deviceId].connectionString;
    }

    const connStr = `HostName=${await getDeviceHub(context, device)};DeviceId=${deviceId};SharedAccessKey=${await getDeviceKey(context, deviceId)}`;
    deviceCache[deviceId].connectionString = connStr;
    return connStr;
}

/**
 * Registers this device with DPS, returning the IoT Hub assigned to it.
 */
async function getDeviceHub(context, device) {
    const deviceId = device.devEui;
    const now = Date.now();

    // A 1 minute backoff is enforced for registration attempts, to prevent unauthorized devices
    // from trying to re-register too often.
    if (deviceCache[deviceId] && deviceCache[deviceId].lasRegisterAttempt && (now - deviceCache[deviceId].lasRegisterAttempt) < minDeviceRegistrationTimeout) {
        const backoff = Math.floor((minDeviceRegistrationTimeout - (now - deviceCache[deviceId].lasRegisterAttempt)) / 1000);
        throw new StatusError(`Unable to register device ${deviceId}. Minimum registration timeout not yet exceeded. Please try again in ${backoff} seconds`, 403);
    }

    deviceCache[deviceId] = {
        ...deviceCache[deviceId],
        lasRegisterAttempt: Date.now()
    }

    const sasToken = await getRegistrationSasToken(context, deviceId);

    url = `https://${registrationHost}/${context.idScope}/registrations/${deviceId}/register?api-version=${registrationApiVersion}`;
    const registrationOptions = {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json', Authorization: sasToken },
        body: JSON.stringify({ registrationId: deviceId, payload: { iotcModelId: device.modelId } })
    };

    try {
        context.log('[HTTP] Initiating device registration');
        const response = await fetch(url, registrationOptions).then(res => res.json());

        if (response.status !== 'assigning' || !response.operationId) {
            throw new Error('Unknown server response');
        }

        url = `https://${registrationHost}/${context.idScope}/registrations/${deviceId}/operations/${response.operationId}?api-version=${registrationApiVersion}`;
        const statusOptions = {
            method: 'GET',
            headers: { Authorization: sasToken }
        };

        // The first registration call starts the process, we then query the registration status
        // every 2 seconds, up to 10 times.
        for (let i = 0; i < registrationStatusQueryAttempts; ++i) {
            await new Promise(resolve => setTimeout(resolve, registrationStatusQueryTimeout));

            context.log('[HTTP] Querying device registration status');
            const statusResponse = await fetch(url, statusOptions).then(res => res.json());

            if (statusResponse.status === 'assigning') {
                continue;
            } else if (statusResponse.status === 'assigned' && statusResponse.registrationState && statusResponse.registrationState.assignedHub) {
                return statusResponse.registrationState.assignedHub;
            } else if (statusResponse.status === 'failed' && statusResponse.registrationState && statusResponse.registrationState.errorCode === 400209) {
                throw new StatusError('The device may be unassociated or blocked', 403);
            } else {
                throw new Error('Unknown server response');
            }
        }

        throw new Error('Registration was not successful after maximum number of attempts');
    } catch (e) {
        throw new StatusError(`Unable to register device ${deviceId}: ${e.message}`, e.statusCode);
    }
}

async function getRegistrationSasToken(context, deviceId) {
    const uri = encodeURIComponent(`${context.idScope}/registrations/${deviceId}`);
    const ttl = Math.round(Date.now() / 1000) + registrationSasTtl;
    const signature = crypto.createHmac('sha256', new Buffer(await getDeviceKey(context, deviceId), 'base64'))
        .update(`${uri}\n${ttl}`)
        .digest('base64');
    return`SharedAccessSignature sr=${uri}&sig=${encodeURIComponent(signature)}&skn=registration&se=${ttl}`;
}

/**
 * Computes a derived device key using the primary key.
 */
async function getDeviceKey(context, deviceId) {
    if (deviceCache[deviceId] && deviceCache[deviceId].deviceKey) {
        return deviceCache[deviceId].deviceKey;
    }

    const key = crypto.createHmac('SHA256', Buffer.from(await context.getSecret(context, context.primaryKeyUrl), 'base64'))
        .update(deviceId)
        .digest()
        .toString('base64');

    deviceCache[deviceId].deviceKey = key;
    return key;
}

function decodeUplink(input) {
  
  var data = {};
  
  var input_bytes = hexToBytes(input.payload);

  data.payload = input.payload;  
  if (input.fPort==3){
    data = decode(input_bytes, [unixtime, latLng], ['unixtime', 'coords']);
    data.type = "location";
    data.datetime = new Date(data.unixtime*1000).toLocaleString("en-GB");
  }
  if (input.fPort==5){
    data = decode(input_bytes, [unixtime], ['unixtime']);
    var behaviours = [];
    for (var x = unixtime.BYTES; x < input_bytes.length; x++) {
      behaviours.push(bitmap(input_bytes.slice(x, x + 1)));
    }
    data.behaviours = behaviours;
    data.type = "activity";
    data.datetime = new Date(data.unixtime*1000).toLocaleString("en-GB");
  }
  return {
    data: data,
    warnings: [],
    errors: []
  };
}

var bytesToInt = function(bytes) {
  var i = 0;
  for (var x = 0; x < bytes.length; x++) {
    i |= +(bytes[x] << (x * 8));
  }
  return i;
};

var unixtime = function(bytes) {
  if (bytes.length !== unixtime.BYTES) {
    throw new Error('Unix time must have exactly 4 bytes');
  }
  return bytesToInt(bytes);
};
unixtime.BYTES = 4;

var uint8 = function(bytes) {
  if (bytes.length !== uint8.BYTES) {
    throw new Error('uint8 must have exactly 1 byte');
  }
  return bytesToInt(bytes);
};
uint8.BYTES = 1;

var uint16 = function(bytes) {
  if (bytes.length !== uint16.BYTES) {
    throw new Error('uint16 must have exactly 2 bytes');
  }
  return bytesToInt(bytes);
};
uint16.BYTES = 2;

var uint32 = function(bytes) {
  if (bytes.length !== uint32.BYTES) {
    throw new Error('uint32 must have exactly 4 bytes');
  }
  return bytesToInt(bytes);
};
uint32.BYTES = 4;

var latLng = function(bytes) {
  if (bytes.length !== latLng.BYTES) {
    throw new Error('Lat/Long must have exactly 8 bytes');
  }

  var lat = bytesToInt(bytes.slice(0, latLng.BYTES / 2));
  var lng = bytesToInt(bytes.slice(latLng.BYTES / 2, latLng.BYTES));

  return [lat / 1e6, lng / 1e6];
};
latLng.BYTES = 8;

var temperature = function(bytes) {
  if (bytes.length !== temperature.BYTES) {
    throw new Error('Temperature must have exactly 2 bytes');
  }
  var isNegative = bytes[0] & 0x80;
  var b = ('00000000' + Number(bytes[0]).toString(2)).slice(-8)
        + ('00000000' + Number(bytes[1]).toString(2)).slice(-8);
  if (isNegative) {
    var arr = b.split('').map(function(x) { return !Number(x); });
    for (var i = arr.length - 1; i > 0; i--) {
      arr[i] = !arr[i];
      if (arr[i]) {
        break;
      }
    }
    b = arr.map(Number).join('');
  }
  var t = parseInt(b, 2);
  if (isNegative) {
    t = -t;
  }
  return t / 1e2;
};
temperature.BYTES = 2;

var humidity = function(bytes) {
  if (bytes.length !== humidity.BYTES) {
    throw new Error('Humidity must have exactly 2 bytes');
  }

  var h = bytesToInt(bytes);
  return h / 1e2;
};
humidity.BYTES = 2;

// Based on https://stackoverflow.com/a/37471538 by Ilya Bursov
// quoted by Arjan here https://www.thethingsnetwork.org/forum/t/decode-float-sent-by-lopy-as-node/8757
function rawfloat(bytes) {
  if (bytes.length !== rawfloat.BYTES) {
    throw new Error('Float must have exactly 4 bytes');
  }
  // JavaScript bitwise operators yield a 32 bits integer, not a float.
  // Assume LSB (least significant byte first).
  var bits = bytes[3]<<24 | bytes[2]<<16 | bytes[1]<<8 | bytes[0];
  var sign = (bits>>>31 === 0) ? 1.0 : -1.0;
  var e = bits>>>23 & 0xff;
  var m = (e === 0) ? (bits & 0x7fffff)<<1 : (bits & 0x7fffff) | 0x800000;
  var f = sign * m * Math.pow(2, e - 150);
  return f;
}
rawfloat.BYTES = 4;

var bitmap = function(byte) {
  if (byte.length !== bitmap.BYTES) {
    throw new Error('Bitmap must have exactly 1 byte');
  }
  var i = bytesToInt(byte);
  
  var sequence_string = ('00000000' + Number(i).toString(2)).substr(-8);
  var results = [];
  for (var j = 0; j < 8; j += 2) {
  	results.push(parseInt(sequence_string.substring(j, j + 2),2));
  }
  //var bm = ('00000000' + Number(i).toString(2)).substr(-8).split('').map(Number);//.map(Boolean);
  return results;
};
bitmap.BYTES = 1;

var decode = function(bytes, mask, names) {

  var maskLength = mask.reduce(function(prev, cur) {
    return prev + cur.BYTES;
  }, 0);
  if (bytes.length < maskLength) {
    throw new Error('Mask length is ' + maskLength + ' whereas input is ' + bytes.length);
  }

  names = names || [];
  var offset = 0;
  return mask
    .map(function(decodeFn) {
      var current = bytes.slice(offset, offset += decodeFn.BYTES);
      return decodeFn(current);
    })
    .reduce(function(prev, cur, idx) {
      prev[names[idx] || idx] = cur;
      return prev;
    }, {});
};

// Convert a hex string to a byte array
function hexToBytes(hex) {
    for (var bytes = [], c = 0; c < hex.length; c += 2)
    bytes.push(parseInt(hex.substr(c, 2), 16));
    return bytes;
}

