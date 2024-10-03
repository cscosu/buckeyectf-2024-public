/*
look man i dont make web apps
i exploit them
*/

const monkeys = [mKey, oKey, nKey, kKey, eKey, yKey]
var keyTimes = [0, 0, 0, 0, 0, 0, 0]
var step = 0

function parsescore(data){
    if (data.status == "anonymous"){
        scorefield.textContent = `Your score: ${data.score.toFixed(2)}`;
    } else if (data.status == "unimproved"){
        scorefield.textContent = `Your score: ${data.score.toFixed(2)}`;
    } else if (data.status == "improved") {
        scorefield.textContent = `Your score: ${data.score.toFixed(2)} (new best!)`;
    }
}

function colorkey(event){
    switch (event.keyCode){
        case 77: // m
            if (step == 0){
                step++;
                keyTimes[1] = Date.now();
                mKey.style.color = "green";
            }
            break;
        case 79: // o
            if (step == 1){
                step++;
                keyTimes[2] = Date.now();
                oKey.style.color = "green";
            }
            break;
        case 78: // n
            if (step == 2){
                step++;
                keyTimes[3] = Date.now();
                nKey.style.color = "green";
            }
            break;
        case 75: // k
            if (step == 3){
                step++;
                keyTimes[4] = Date.now();
                kKey.style.color = "green";
            }
            break;
        case 69: // e
            if (step == 4){
                step++;
                keyTimes[5] = Date.now();
                eKey.style.color = "green";
            }
            break;
        case 89: // y
            if (step == 5){
                step++;
                keyTimes[6] = Date.now();
                yKey.style.color = "green";
                subkeys = [0,0,0,0,0,0];
                for (var i = 0; i < subkeys.length; i++){
                    subkeys[i] = (keyTimes[i+1] - keyTimes[i])/1000;
                }
                var score = 0;
                fetch("/api/score/submit", {
                    method: "POST",
                    headers: {
                      "Content-Type": "application/json",
                    },
                    body: JSON.stringify({ counts: subkeys }),
                  }).then(
                    response => response.json()
                  ).then(
                    data => parsescore(data)
                  );
            }
            // console.log(keyTimes);
            break;
        default:
            break;

    }
}

function rand_time() {
    return Math.random() * (10 - 3) + 3;
  }
  

startButton.addEventListener("click", function (e) {
    monkeyimage.style.visibility = "hidden"
    monkeyimage.src = "https://www.placemonkeys.com/300?random&" + new Date().getTime();
    waiter.textContent = "wait..."
    scorefield.textContent = ""
    document.removeEventListener("keydown", colorkey, false);
    step = 0;
    startButton.disabled = true;
    for (const key of monkeys){
        key.style.color = 'black'
        key.style.visibility = 'visible'
    };
    waiter.style.visibility = 'visible';
    timeToWait = rand_time()*1000; // wait between 1 and 6 secs
    console.log(timeToWait)
    setTimeout(monkey_type, timeToWait)
  });

function monkey_type(){
    for (const key of monkeys){
        key.style.color = 'red'
    };
    document.addEventListener("keydown", colorkey, false);
    monkeyimage.style.visibility = "visible"
    keyTimes[0] = Date.now()
    waiter.textContent = "TYPE!!!"
    startButton.disabled = false;
}
  