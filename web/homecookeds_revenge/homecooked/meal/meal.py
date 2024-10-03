from lark import Lark, Tree, Token
from lark.visitors import Interpreter
from homecooked.waf.blocked_names import blocked_names
import os
import glob
from markupsafe import escape

# use markupsafe escape function to escape html for now. Don't want to deal with html parsing
# and differentiating between server-injected html and user-injected html

# Meal is a simple templating engine that uses Lark for parsing and interpreting templates.
# Meal is only XSS safe via the recursive-escape method.

# modified from Lark Python reference
# https://raw.githubusercontent.com/lark-parser/lark/master/lark/grammars/python.lark

cwd = os.path.dirname(os.path.realpath(__file__))

with open(os.path.join(cwd, 'meal.lark'), 'r') as f:
    MealGrammar = Lark(f.read(), start='body', parser='lalr')

def recursive_escape(data):
    if isinstance(data, dict):
        res = {}
        for k, v in data.items():
            k_esc = escape(k)

            res[k_esc] = recursive_escape(v)
    elif isinstance(data, list):
        res = []
        for v in data:
            res.append(recursive_escape(v))
    else:
        res = escape(str(data))
    
    return res

class MealInterpreter(Interpreter):     
    def __init__(self) -> None:
        super().__init__()
        self.state = {}
        self.builtins = {
            'range': range,
            'len': len,
            'max': max,
            'min': min,
            'sum': sum,
            'abs': abs,
            'round': round,
            'ord': ord,
            'chr': chr,
            'hex': hex,
            'oct': oct,
            'bin': bin,
            'int': int,
            'float': float,
            'complex': complex,
            'str': str,
            'join': ''.join,
            'list': list,
            'type': type,
            'object': object,
        }

        self.arith_ops = {
            '🍦': lambda x, y: x + y,
            '🍧': lambda x, y: x - y,
            '🍨': lambda x, y: x * y,
            '🍩': lambda x, y: x / y,
            '🍪': lambda x, y: x // y,
            '🎂': lambda x, y: x % y
        }
        self.compare_ops = {
            '🍰': lambda x, y: x < y,
            '🧁': lambda x, y: x > y,
            '🥧': lambda x, y: x == y,
            '🍫': lambda x, y: x >= y,
            '🍬': lambda x, y: x <= y,
            '🍭': lambda x, y: x != y
        }
        self.unary_ops = {
            '🥟': lambda x: x,
            '🥠': lambda x: -x,
            '🥡': lambda x: ~x
        }
        self.is_last_html = False

    def body(self, tree):
        res = ''.join(self.visit_children(tree))
        return res

    def statement(self, tree):
        return self.visit(tree.children[0])
    
    def eval(self, tree):
        return str(self.visit(tree.children[0]))
        
    def html(self, tree):
        res = self.visit_children(tree.children[1])
        return tree.children[0] + ''.join(res)
    
    def meal_literal(self, tree):
        return tree.children[0].value

    def simple_statement(self, tree):
        return self.visit(tree.children[0])
    
    def compound_statement(self, tree):
        return self.visit(tree.children[0])
    
    def for_stmt(self, tree):
        name = self.visit(tree.children[0])
        temp = False

        if name not in self.state:
            self.state[name] = None
            temp = True

        expr = self.visit(tree.children[1])

        res = []

        for i in range(len(expr)):
            self.state[name] = expr[i]
            res.append(self.visit(tree.children[2]))

        if temp:
            del self.state[name]
        return ''.join(res)
    
    def if_stmt(self, tree):
        expr = self.visit(tree.children[0])

        if expr:
            return self.visit(tree.children[1])
        
        for i in range(2, len(tree.children), 2):
            if tree.children[i].data == 'else':
                return self.visit(tree.children[i + 1])
            elif self.visit(tree.children[i]):
                return self.visit(tree.children[i + 1])
            
        return ''
    
    def while_stmt(self, tree):
        res = ''
        while self.visit(tree.children[0]):
            res += self.visit(tree.children[1])
        return res
    
    def assign_stmt(self, tree):
        name = self.visit(tree.children[0])

        self.state[name] = self.visit(tree.children[1])
        return ''

    def expression(self, tree):
        return self.visit(tree.children[0])
    
    def test(self, tree): 
        expr1 = self.visit(tree.children[0])

        if len(tree.children) == 1:
            return expr1
        
        if expr1:
            return self.visit(tree.children[1])
        return self.visit(tree.children[2])
    
    def or_test(self, tree):
        expr1 = self.visit(tree.children[0])

        if len(tree.children) == 1:
            return expr1
        
        expr2 = self.visit(tree.children[2])

        return expr1 or expr2
    
    def and_test(self, tree):
        expr1 = self.visit(tree.children[0])

        if len(tree.children) == 1:
            return expr1
        
        expr2 = self.visit(tree.children[2])

        return expr1 and expr2
    
    def not_test(self, tree):
        if tree.children[0].data == 'not_test':
            return not self.visit(tree.children[0])
        
        return self.visit(tree.children[0])
    
    def comparison(self, tree):
        expr1 = self.visit(tree.children[0])

        if len(tree.children) == 1:
            return expr1
        
        op = self.compare_ops[self.visit(tree.children[1])]
        expr2 = self.visit(tree.children[2])

        return op(expr1, expr2)
    
    def arith_expr(self, tree):
        term1 = self.visit(tree.children[0])

        if len(tree.children) == 1:
            return term1
        
        op = self.arith_ops[self.visit(tree.children[1])]
        term2 = self.visit(tree.children[2])

        return op(term1, term2)
    
    def term(self, tree):
        factor1 = self.visit(tree.children[0])

        if len(tree.children) == 1:
            return factor1
        
        op = self.arith_ops[self.visit(tree.children[1])]
        factor2 = self.visit(tree.children[2])

        return op(factor1, factor2)
    
    def factor(self, tree):
        if tree.children[0].type == 'UNARY_OP':
            op = self.unary_ops[self.visit(tree.children[0])]
            return op(self.visit(tree.children[1]))
        
        return self.visit(tree.children[0])
    
    def power(self, tree):
        expr = self.visit(tree.children[0])

        if len(tree.children) == 1:
            return expr
        
        return expr ** self.visit(tree.children[1])
    
    def atom_expr(self, tree):
        return self.visit(tree.children[0])
    
    def list(self, tree):
        if tree.children:
            return [self.visit(child) for child in tree.children]
        
        return []
    
    def funccall(self, tree):    
        name = self.visit(tree.children[0])
        args, kwargs = self.visit(tree.children[1]) if tree.children[1] is not None else ([], {})
        return name(*args, **kwargs)
    
    def getitem(self, tree):
        name = self.visit(tree.children[0])
        subscripts = self.visit(tree.children[1])

        return name[subscripts]
    
    def getattr(self, tree):
        name = self.visit(tree.children[0])
        attr = self.visit(tree.children[1])

        if attr not in self.state:
            raise AttributeError(f"Object has no attribute '{attr}'")
                
        if name not in set(self.builtins.values()) and name not in self.state:
            raise AttributeError(f"Object '{name}' is not defined")
        
        if name in set(self.builtins.values()) and hasattr(name, attr):
            raise AttributeError(f"Builtins have no accessible attribute '{attr}'")

        if isinstance(name, dict):
            return name[attr]
        elif hasattr(name, attr):
            return getattr(name, attr)
        elif attr in self.state:
            value = self.state[attr]

            if value is None or value.lower() in blocked_names:
                raise ValueError(f"Attribute '{value}' is blocked on object '{name}'")

            return getattr(name, self.state[attr])
        
        raise AttributeError(f"Object has no attribute '{attr}'")
    
    def atom(self, tree):
        child = tree.children[0]

        if isinstance(child, Tree):
            name = self.visit(child)
        else:
            name = child.value
        
        return name
    
    def subscript_list(self, tree):
        expr1 = self.visit(tree.children[0])

        if len(tree.children) == 1:
            return expr1
        
        res = [expr1]

        res.extend([self.visit(child) for child in tree.children[1:]])

        return res
    
    def subscript(self, tree):
        if len(tree.children) == 1:
            return self.visit(tree.children[0])
        
        return self.visit(tree.children[0]), self.visit(tree.children[1])
    
    def sliceop(self, tree):
        if tree.children:
            return self.visit(tree.children[0])
        
        return None

    def exprlist(self, tree):
        return [self.visit(child) for child in tree.children]
    
    def testlist(self, tree):
        return [self.visit(child) for child in tree.children]
    
    def testlist_tuple(self, tree):
        return [self.visit(child) for child in tree.children]
    
    def arguments(self, tree):
        kwargs = {}
        args = []

        for child in tree.children:
            res = self.visit(child)
            
            if isinstance(res, tuple):
                kwargs[res[0]] = res[1]
            else:
                args.append(res)
        
        return args, kwargs
    
    def argvalue(self, tree):
        if len(tree.children) == 1:
            return self.visit(tree.children[0])
        
        key = self.visit(tree.children[0])
        value = self.visit(tree.children[1])
        
        return key, value
    
    def kwargvalue(self, tree):
        return self.visit(tree.children[0])
    
    def number(self, tree):
        child = tree.children[0]
        if child.type == 'DEC_NUMBER':
            return int(child.value)
        elif child.type == 'HEX_NUMBER':
            return int(child.value, 16)
        elif child.type == 'BIN_NUMBER':
            return int(child.value, 2)
        elif child.type == 'OCT_NUMBER':
            return int(child.value, 8)
        elif child.type == 'FLOAT_NUMBER':
            return float(child.value)
        elif child.type == 'IMAG_NUMBER':
            return complex(child.value)
        
        raise ValueError(f"Invalid number type: {child.value}")

    def interpret(self, context, tree: Tree) -> Tree:
        self.state = context.copy()
        res = self.visit(tree)
        res = res.replace('\n', '')
        return '\n<'.join(res.split("<"))
    
    def name(self, tree):
        res = self.visit(tree.children[0])

        if res.lower() in blocked_names:
            raise ValueError(f"Name '{res}' is blocked")

        return res
    
    def var(self, tree):
        name = self.visit(tree.children[0])
        if name in self.state:
            return self.state[name]
        elif name in self.builtins:
            return self.builtins[name]
        
        return name # this will boil up errors if name is undefined and used for something not a keyword
                
    def string(self, tree):
        return tree.children[0].value[1:-1]
    
    def true(self, tree):
        return True
    
    def false(self, tree):
        return False
    
    def none(self, tree):
        return None

    def visit(self, child):
        if isinstance(child, Token):
            return child.value
        
        return super().visit(child)
    
class MealManager:
    def __init__(self, template_dir, grammar = MealGrammar) -> None:
        path = os.path.join(os.getcwd(), template_dir)
        self.templates = {}
        self.grammar = grammar
        self.interpreter = MealInterpreter()

        self._load_templates(path)

    def _load_templates(self, path):
        templates = glob.glob(os.path.join(path, "**/*.html"), recursive=True)

        for template_path in templates:
            with open(template_path, 'r', encoding='utf-8') as f:
                template = f.read()
                name = os.path.relpath(template_path, path)
                tree = self.grammar.parse(template)
                self.templates[name] = tree

    def interpret(self, template_name, context):
        if template_name not in self.templates:
            raise FileNotFoundError(f"Template '{template_name}' not found")
        
        context = recursive_escape(context)   
        try:     
            return self.interpreter.interpret(context, self.templates[template_name])
        except Exception as e:
            return f"Error in template '{template_name}': {e}"
        
    @classmethod
    def interpret_string(cls, template_string, context):
        try:
            tree = MealGrammar.parse(template_string)
            interpreter = MealInterpreter()
            context = recursive_escape(context)
            return interpreter.interpret(context, tree)
        except Exception as e:
            return f"Error in template: {e}"