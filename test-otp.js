#!/usr/bin/env node
/**
 * OTP Testing Script
 * Tests OTP generation and Twilio SMS sending
 */

require('dotenv').config();
const twilio = require('twilio');
const crypto = require('crypto');

// Configuration
const twilioAccountSid = process.env.TWILIO_ACCOUNT_SID || '';
const twilioAuthToken = process.env.TWILIO_AUTH_TOKEN || '';
const twilioMessagingServiceSid = process.env.TWILIO_MESSAGING_SERVICE_SID || '';
const twilioSmsFrom = process.env.TWILIO_SMS_FROM || '';
const OTP_LENGTH = parseInt(process.env.OTP_LENGTH || '4', 10);

console.log('\n' + '='.repeat(70));
console.log('OTP TESTING SCRIPT');
console.log('='.repeat(70));

// Check configuration
console.log('\n📋 Configuration Check:');
console.log(`  - Account SID: ${twilioAccountSid ? '✅ Set' : '❌ Missing'}`);
console.log(`  - Auth Token: ${twilioAuthToken ? '✅ Set' : '❌ Missing'}`);
console.log(`  - Messaging Service SID: ${twilioMessagingServiceSid || 'Not set'}`);
console.log(`  - SMS From: ${twilioSmsFrom || 'Not set'}`);
console.log(`  - OTP Length: ${OTP_LENGTH}`);

// Test OTP generation
console.log('\n🔢 Testing OTP Generation:');
function generateOtpCode() {
  const min = Math.pow(10, Math.max(OTP_LENGTH - 1, 1));
  const max = Math.pow(10, OTP_LENGTH) - 1;
  const randomNum = crypto.randomInt(min, max + 1);
  return randomNum.toString().padStart(OTP_LENGTH, '0');
}

const testOtp = generateOtpCode();
console.log(`  - Generated OTP: ${testOtp}`);
console.log(`  - Length: ${testOtp.length}`);
console.log(`  - Valid: ${testOtp.length === OTP_LENGTH && /^\d+$/.test(testOtp) ? '✅' : '❌'}`);

// Test Twilio client
console.log('\n📱 Testing Twilio Client:');
if (!twilioAccountSid || !twilioAuthToken) {
  console.log('  ❌ Twilio credentials not configured');
  console.log('\n💡 To fix: Set TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN in .env file');
  process.exit(1);
}

const twilioClient = twilio(twilioAccountSid, twilioAuthToken);
console.log('  ✅ Twilio client initialized');

// Test SMS sending (if phone number provided)
const testPhoneNumber = process.argv[2];

if (testPhoneNumber) {
  console.log(`\n📤 Testing SMS Send to: ${testPhoneNumber}`);
  
  const destination = testPhoneNumber.startsWith('+') ? testPhoneNumber : `+91${testPhoneNumber.replace(/\D/g, '')}`;
  const messageBody = `Your Cyano Veda test OTP is ${testOtp}. This is a test message.`;
  
  const payload = {
    to: destination,
    body: messageBody
  };
  
  if (twilioMessagingServiceSid && twilioMessagingServiceSid !== 'xxxxxxxxxx') {
    payload.messagingServiceSid = twilioMessagingServiceSid;
    console.log(`  - Using Messaging Service: ${twilioMessagingServiceSid}`);
  } else if (twilioSmsFrom && twilioSmsFrom !== 'xxxxxxxxxx') {
    payload.from = twilioSmsFrom;
    console.log(`  - Using From Number: ${twilioSmsFrom}`);
  } else {
    console.log('  ❌ No valid Messaging Service SID or From Number configured');
    process.exit(1);
  }
  
  twilioClient.messages.create(payload)
    .then(message => {
      console.log('\n✅ SMS SENT SUCCESSFULLY!');
      console.log(`  - SID: ${message.sid}`);
      console.log(`  - Status: ${message.status}`);
      console.log(`  - To: ${message.to}`);
      console.log(`  - From: ${message.from}`);
      console.log('\n' + '='.repeat(70));
    })
    .catch(error => {
      console.log('\n❌ SMS SEND FAILED!');
      console.log(`  - Error: ${error.message}`);
      console.log(`  - Code: ${error.code}`);
      if (error.moreInfo) console.log(`  - More Info: ${error.moreInfo}`);
      console.log('\n💡 Common Issues:');
      console.log('  1. Invalid Twilio credentials');
      console.log('  2. Messaging Service not configured correctly');
      console.log('  3. Phone number not verified (trial account)');
      console.log('  4. Insufficient Twilio balance');
      console.log('  5. Network/firewall blocking Twilio API');
      console.log('\n' + '='.repeat(70));
      process.exit(1);
    });
} else {
  console.log('\n💡 To test SMS sending, run:');
  console.log(`   node test-otp.js <phone_number>`);
  console.log('   Example: node test-otp.js 9876543210');
  console.log('\n' + '='.repeat(70));
}
