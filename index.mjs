import { S3Client, DeleteObjectCommand } from "@aws-sdk/client-s3";
import { CloudTrailClient, LookupEventsCommand } from "@aws-sdk/client-cloudtrail";
import { SESClient, SendEmailCommand } from "@aws-sdk/client-ses";
import { SecretsManagerClient, GetSecretValueCommand } from "@aws-sdk/client-secrets-manager";

// Instantiate AWS clients outside the handler for reuse
const s3Client = new S3Client({});
const cloudTrailClient = new CloudTrailClient({});
const sesClient = new SESClient({});
const secretsManagerClient = new SecretsManagerClient({});

// --- Placeholder for Crowdstrike API Interaction ---
// In a real-world scenario, you would use an HTTP client like fetch or axios
// to call the Crowdstrike API endpoint for scanning S3 objects.
async function scanWithCrowdstrike(bucket, key) {
    console.log(`Initiating Crowdstrike scan for s3://${bucket}/${key}`);
    
    // 1. Fetch Crowdstrike API credentials from Secrets Manager
    // const secretCommand = new GetSecretValueCommand({ SecretId: process.env.CROWDSTRIKE_SECRET_ARN });
    // const secretResponse = await secretsManagerClient.send(secretCommand);
    // const crowdstrikeCredentials = JSON.parse(secretResponse.SecretString);
    // const { apiKey, apiSecret } = crowdstrikeCredentials;

    // 2. Make the actual API call to Crowdstrike
    // This is a MOCK implementation. You must replace this with your actual API call.
    // The API might require the file's S3 URI or a pre-signed URL.
    // const response = await fetch('https://api.crowdstrike.com/malware-scan/v1/...', {
    //   method: 'POST',
    //   headers: { 'Authorization': `Bearer ${apiKey}` ... },
    //   body: JSON.stringify({ s3_uri: `s3://${bucket}/${key}` })
    // });
    // const scanResult = await response.json();

    // 3. For this example, we'll simulate a malicious finding if the filename contains "malicious".
    if (key.toLowerCase().includes("malicious")) {
        console.warn("MOCK SCAN: File flagged as MALICIOUS.");
        return {
            isMalicious: true,
            details: "Simulated detection: EICAR Test File"
        };
    }

    console.log("MOCK SCAN: File is clean.");
    return { isMalicious: false, details: "Scan complete. No threats found." };
}

// --- Helper to find uploader details from CloudTrail ---
async function getUploadDetailsFromCloudTrail(bucket, key, eventTime) {
    // CloudTrail events can have a delay. We'll search a 15-minute window around the event time.
    const startTime = new Date(eventTime);
    startTime.setMinutes(startTime.getMinutes() - 15);

    const command = new LookupEventsCommand({
        LookupAttributes: [{
            AttributeKey: "EventName",
            AttributeValue: "PutObject"
        }],
        StartTime: startTime,
        EndTime: new Date(eventTime)
    });

    try {
        const { Events } = await cloudTrailClient.send(command);
        
        // Find the specific event that matches our S3 object
        for (const event of Events) {
            const cloudTrailEvent = JSON.parse(event.CloudTrailEvent);
            const requestParams = cloudTrailEvent.requestParameters;

            if (requestParams && requestParams.bucketName === bucket && requestParams.key === key) {
                return {
                    user: cloudTrailEvent.userIdentity.arn || cloudTrailEvent.userIdentity.principalId,
                    ipAddress: cloudTrailEvent.sourceIPAddress,
                    uploadTime: cloudTrailEvent.eventTime
                };
            }
        }
    } catch (error) {
        console.error("Error looking up CloudTrail events:", error);
    }
    
    // Return defaults if the event is not found (e.g., due to latency)
    return {
        user: "Not Found (CloudTrail Latency)",
        ipAddress: "Not Found",
        uploadTime: eventTime
    };
}


// --- Main Lambda Handler ---
export const handler = async (event) => {
    console.log("Received S3 event:", JSON.stringify(event, null, 2));

    const record = event.Records[0];
    const bucket = record.s3.bucket.name;
    const key = decodeURIComponent(record.s3.object.key.replace(/\+/g, ' '));
    const eventTime = record.eventTime;

    console.log(`Processing file: ${key} from bucket: ${bucket}`);

    try {
        // 1. Scan the file with Crowdstrike
        const scanResult = await scanWithCrowdstrike(bucket, key);

        if (scanResult.isMalicious) {
            console.log(`Malicious file detected: ${key}. Deleting and notifying.`);

            // 2. Get uploader details from CloudTrail
            const uploadDetails = await getUploadDetailsFromCloudTrail(bucket, key, eventTime);

            // 3. Delete the malicious object from S3
            const deleteCommand = new DeleteObjectCommand({ Bucket: bucket, Key: key });
            await s3Client.send(deleteCommand);
            console.log(`Successfully deleted s3://${bucket}/${key}`);

            // 4. Send an email notification
            const subject = `[SECURITY ALERT] Malicious File Deleted from S3`;
            const body = `
A file uploaded to the S3 bucket '${bucket}' was identified as malicious by Crowdstrike and has been automatically deleted.

Please review the details below:

- **File Name**: ${key}
- **Scan Details**: ${scanResult.details}
- **Uploader Principal**: ${uploadDetails.user}
- **Source IP Address**: ${uploadDetails.ipAddress}
- **Upload Timestamp**: ${uploadDetails.uploadTime}

This action was performed automatically by the S3 security scanning system.
            `;

            const emailCommand = new SendEmailCommand({
                Destination: { ToAddresses: [process.env.NOTIFICATION_EMAIL_TO] },
                Message: {
                    Body: { Text: { Data: body } },
                    Subject: { Data: subject },
                },
                Source: process.env.NOTIFICATION_EMAIL_FROM,
            });
            await sesClient.send(emailCommand);
            console.log(`Security notification sent to ${process.env.NOTIFICATION_EMAIL_TO}`);
        } else {
            console.log(`File s3://${bucket}/${key} is clean.`);
        }
        
        return {
            statusCode: 200,
            body: JSON.stringify({ message: "Scan complete.", status: scanResult.isMalicious ? "Malicious" : "Clean" }),
        };

    } catch (error) {
        console.error("An error occurred in the handler:", error);
        // You might want to add error notifications here as well
        throw error;
    }
};