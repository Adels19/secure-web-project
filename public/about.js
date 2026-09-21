const statusLine = document.getElementById('status-line');
if (window.location.protocol === 'https:') {
  statusLine.textContent = 'This page was loaded securely over HTTPS/TLS.';
  statusLine.classList.add('secure');
} else {
  statusLine.textContent = 'Warning: this page is NOT loaded over HTTPS.';
}

const demoInput = document.getElementById('demo-input');
const demoButton = document.getElementById('demo-button');
const demoOutput = document.getElementById('demo-output');

demoButton.addEventListener('click', () => {
  const userText = demoInput.value;

  if (userText.trim().length === 0) {
    demoOutput.textContent = userText;
    return;
  }

  demoOutput.textContent = userText; // SAFE - never innerHTML with untrusted text
});