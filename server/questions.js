
// Hardcoded assessment content - deliberately no database, per project scope.
// Teachers can add, edit, or delete questions through the
// "Manage Questions" feature. These changes are kept only in memory
// and will be lost when the server is restarted.

const ASSESSMENT = {
  title: 'Network Security Fundamentals',
  instructions: 'Answer all 5 questions, then submit.',
  questions: [
    { id: 'q1', prompt: 'What does PKI stand for?', choices: ['Public Key Infrastructure', 'Private Key Identity', 'Protocol Key Interchange', 'Public Key Interchange'], correctIndex: 0 },
    { id: 'q2', prompt: 'Which protocol secures HTTP traffic in transit?', choices: ['FTP', 'TLS', 'SMTP', 'SSH'], correctIndex: 1 },
    { id: 'q3', prompt: 'What does a Certificate Authority (CA) do?', choices: ['Encrypts all network traffic', 'Stores user passwords', 'Signs and vouches for certificates', 'Blocks malicious IP addresses'], correctIndex: 2 },
    { id: 'q4', prompt: 'In mutual TLS (mTLS), who presents a certificate?', choices: ['Only the server', 'Only the client', 'Both the client and the server', 'Neither party'], correctIndex: 2 },
    { id: 'q5', prompt: 'What does SAN stand for in a certificate?', choices: ['Server Authentication Name', 'Subject Alternative Name', 'Secure Access Node', 'Signed Authority Number'], correctIndex: 1 }
  ]
};

module.exports = { ASSESSMENT };