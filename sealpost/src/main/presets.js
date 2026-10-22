/* =====================================================================
 * Sealpost — presets.js
 * Server settings for common providers (fills the account form).
 * Notes tell the user about app passwords etc.
 * ===================================================================== */
module.exports = [
  {
    id: 'gmail', label: 'Gmail / Google Workspace',
    imapHost: 'imap.gmail.com', imapPort: 993, imapSecurity: 'ssl',
    smtpHost: 'smtp.gmail.com', smtpPort: 465, smtpSecurity: 'ssl',
    note: 'Turn on 2-Step Verification, then create an App Password (Google Account > Security > App passwords) and use it as the password here.'
  },
  {
    id: 'outlook', label: 'Outlook.com / Hotmail',
    imapHost: 'outlook.office365.com', imapPort: 993, imapSecurity: 'ssl',
    smtpHost: 'smtp-mail.outlook.com', smtpPort: 587, smtpSecurity: 'starttls',
    note: 'Microsoft requires OAuth for many accounts; if password login is refused, enable IMAP in Outlook settings and use an app password, or use Proton/Fastmail etc.'
  },
  {
    id: 'yahoo', label: 'Yahoo Mail',
    imapHost: 'imap.mail.yahoo.com', imapPort: 993, imapSecurity: 'ssl',
    smtpHost: 'smtp.mail.yahoo.com', smtpPort: 465, smtpSecurity: 'ssl',
    note: 'Generate an app password in Yahoo Account Security.'
  },
  {
    id: 'icloud', label: 'iCloud Mail',
    imapHost: 'imap.mail.me.com', imapPort: 993, imapSecurity: 'ssl',
    smtpHost: 'smtp.mail.me.com', smtpPort: 587, smtpSecurity: 'starttls',
    note: 'Use an app-specific password from appleid.apple.com. Username is the part before @icloud.com for some accounts.'
  },
  {
    id: 'fastmail', label: 'Fastmail',
    imapHost: 'imap.fastmail.com', imapPort: 993, imapSecurity: 'ssl',
    smtpHost: 'smtp.fastmail.com', smtpPort: 465, smtpSecurity: 'ssl',
    note: 'Create an app password under Settings > Privacy & Security.'
  },
  {
    id: 'proton', label: 'Proton Mail (via Proton Bridge)',
    imapHost: '127.0.0.1', imapPort: 1143, imapSecurity: 'starttls',
    smtpHost: '127.0.0.1', smtpPort: 1025, smtpSecurity: 'starttls',
    allowSelfSigned: true,
    note: 'Requires Proton Mail Bridge running on this PC. Use the Bridge password, not your Proton password.'
  },
  {
    // 1.7.0: paid Zoho plans and Zoho Workplace use the "pro" servers
    id: 'zohopro', label: 'Zoho Mail (paid plans / Workplace)',
    imapHost: 'imappro.zoho.com', imapPort: 993, imapSecurity: 'ssl',
    smtpHost: 'smtppro.zoho.com', smtpPort: 465, smtpSecurity: 'ssl',
    note: 'Enable IMAP access in Zoho Mail settings. With two-factor sign-in, use an application-specific password.'
  },
  {
    id: 'zoho', label: 'Zoho Mail (free)',
    imapHost: 'imap.zoho.com', imapPort: 993, imapSecurity: 'ssl',
    smtpHost: 'smtp.zoho.com', smtpPort: 465, smtpSecurity: 'ssl',
    note: 'Enable IMAP access in Zoho Mail settings.'
  },
  {
    id: 'cpanel', label: 'cPanel / shared hosting',
    imapHost: 'mail.yourdomain.com', imapPort: 993, imapSecurity: 'ssl',
    smtpHost: 'mail.yourdomain.com', smtpPort: 465, smtpSecurity: 'ssl',
    note: 'Replace yourdomain.com with your domain. Username is usually the full email address. Check "Connect Devices" in cPanel for exact values.'
  },
  {
    id: 'custom', label: 'Other (manual)',
    imapHost: '', imapPort: 993, imapSecurity: 'ssl',
    smtpHost: '', smtpPort: 465, smtpSecurity: 'ssl',
    note: ''
  }
];
