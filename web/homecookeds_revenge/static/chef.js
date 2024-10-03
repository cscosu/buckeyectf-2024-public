let editor = document.getElementById('editor');
let submit = document.getElementById('submit');
let errorMessage = document.getElementById('error-message');
let errorWrapper = document.getElementById('error-wrapper');
let output = document.getElementById('output');

output.hidden = true;
errorWrapper.hidden = true;

submit.addEventListener('click', async () => {
    let text = editor.value;

    if (!text) {
        errorWrapper.hidden = false;
        errorMessage.innerHTML = 'Please enter some text';
        return;
    }

    let res = await fetch('/chef/upload', {
        method: 'POST',
        body: JSON.stringify({text}),
        headers: {
            'Content-Type': 'application/json'
        }
    });

    if (res.status != 200) {
        errorWrapper.hidden = false;
        errorMessage.innerHTML = `The server returned a ${res.status} status code: ${await res.text()}`;
        output.hidden = true;
        return;
    } else {
        errorWrapper.hidden = true;
    }

    setOutput(await res.text());
});

const setOutput = (data) => {
    output.innerHTML = data
    output.hidden = false;
}

const closeError = () => {
    errorWrapper.hidden = true;
}