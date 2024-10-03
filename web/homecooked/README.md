## About

Author: `v0rtex`

`web` `hard`

Server-side template injection

Homecooked is a ASGI-compliant web framework similar to Flask and FastAPI. It includes
support for dynamic routing of paths and middleware, and also features a static server.
Through PyDantic, Homecooked is able to deserialize JSON requests to Python objects and
via the Meal Template Engine, Homecooked supports it's own, very special, templating language.
It also has support for SubRouters, which is Homecooked's equivalent to Blueprints in Flask.

Meal consists entirely of emojis and literals, and well as user-defined variables (which can 
be emojis). See homecooked/meal/meal.lark for grammar reference

## Solve

Run solve.py. This sends a payload to the vulnerable endpoint ? that will respond with the
flag.

Explanation of payload:
```
    🍴 a🍇""🥚__class__🥚__mro__🍎1🍏🥚__subclasses__🦀🦞🍎261🍏🦀🍎"cat"🌭"flag.txt"🍏🌭stdout🍇🥠1🦞🍴
    🥢a🥚stdout🥚read🦀🦞🥢
```
This is equivalent to 
```
    {% a="".__class__.__mro__[1].__subclasses__()[261](["cat","flag.txt"],stdout=-1) %}
    {% a.stdout.read() %}
```
When the emojis are substituted for their python equivalent. The first line uses Python's Method Resolution Order (MRO) to get a reference to the 'object' class. From this, we find all subclasses of object (any class in current execution scope). Via manually inspecting the array returned from subclasses(), we found that `subprocess.Popen` is the 262nd class in the array of subclasses. We then open a subprocess with `stdout=-1`, which is equivalent to `stdout=subprocess.PIPE`. 

To read the result, we just read the value of `a.stdout`, which as the emojified HTMl is an expression,
will lead to the output of the expression (the flag) being returned on the page when rendered.