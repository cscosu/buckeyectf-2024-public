import secrets
import networkx as nx
import random
from z3 import *

FLAG = b"bctf{l0g1c_pr0gr4mm1ng_i5_c00l_i_guess_" + secrets.token_hex(64).encode('utf-8') + b"}"

def soduku(start, end):
    assert end-start == 81
    base  = 3
    side  = base*base

    def pattern(r,c): return (base*(r%base)+r//base+c)%side

    from random import sample
    def shuffle(s): return sample(s,len(s)) 
    rBase = range(base)
    rows  = [ g*base + r for g in shuffle(rBase) for r in shuffle(rBase) ]
    cols  = [ g*base + c for g in shuffle(rBase) for c in shuffle(rBase) ]
    nums  = shuffle(range(base*base))

    board = [ [nums[pattern(r,c)] for c in cols] for r in rows ]

    s = Solver()
    X = [ [ Int("x_%s_%s" % (r+1, c+1)) for c in range(side) ] for r in range(side) ]

    # Add crossword constraints
    for r in range(side):
        for c in range(side):
            s.add(0 <= X[r][c], X[r][c] < side)
    for r in range(side):
        s.add(Distinct(X[r]))
    for c in range(side):
        s.add(Distinct([ X[r][c] for r in range(side) ]))
    
    for r in range(base):
        for c in range(base):
            s.add(Distinct([ X[r*base+i][c*base+j] for i in range(base) for j in range(base) ]))
    
    assert s.check(And([X[r][c] == board[r][c] for r in range(side) for c in range(side)])) == sat

    # Randomly sample 17 numbers, check that the solution is unique
    while True:
        positions = random.sample([(r,c) for r in range(side) for c in range(side)], 30)
        c = And([X[r][c] == board[r][c] for (r,c) in positions])

        if s.check(And(c, Or([X[r][c] != board[r][c] for r in range(side) for c in range(side)]))) == unsat:
            break
        print("retry")
    
    seq = "".join(chr(ord('A') + board[r][c]) for r in range(side) for c in range(side))
    constraints1 = "\n".join(f"cc {r} {c} {board[r][c]}" for (r,c) in positions)

    constraints2 = "\n"
    i = 0
    for r in range(side):
        for c in range(side):
            constraints2 += f"cv {start+i} {r} {c}\n"
            i += 1
    return seq, (constraints1 + constraints2)

seq, soduku_constraints = soduku(48, 48+81)
FLAG = FLAG[:48] + seq.encode('utf-8') + FLAG[48+81:]

def part1(flag, start, end):
    flag = flag[start:end]
    s = ""
    for i in range(len(flag) * 8):
        s += f"av {start*8+i} {i*2}\n"

    soln = []
    soln_sym = []
    solver = Solver()
    for (idx, c) in enumerate(flag):
        for i in range(8):
            soln.append((c >> i) & 1 != 0)
            soln.append((c >> i) & 1 == 0)
            v = Bool(f"{idx}_{i}")
            soln_sym.append(v)
            soln_sym.append(Not(v))

    soln = list(enumerate(soln))

    var = []
    for i in range(5000):
        while True:
            c = random.sample(soln, random.randrange(2, 6))
            if all(not v for (_, v) in c):
                continue
            for (v, _) in c:
                s += f"ac {v} {i}\n"

            solver.add(Or([soln_sym[v] for (v, _) in c]))

            break

    solver.add(Or([soln_sym[v] != soln[v][1] for (v, _) in c]))
    assert solver.check() == unsat

    return s

def part2(flag, start, end):
    flag = flag[start:end]
    print(f"part2: {flag}")
    s = ""
    for i in range(len(flag) * 8):
        s += f"bv {start*8+i} {i+1}\n"

    soln = []
    soln_sym = []
    solver = Solver()
    for (idx, c) in enumerate(flag):
        for i in range(8):
            soln.append((c >> i) & 1 != 0)
            v = Bool(f"{idx}_{i}")
            soln_sym.append(v)

    soln = list(enumerate(soln))

    var = []
    for i in range(5000):
        while True:
            c = random.sample(soln, 3)
            count = random.randrange(3)
            for j in range(count):
                c[j] = (c[j][0], not c[j][1])

            random.shuffle(c)
            s += f"bc " + " ".join(str((v+1) * (1 if sign else -1)) for (v, sign) in c) + "\n"

            solver.add(Or([(soln_sym[v] if sign else Not(soln_sym[v])) for (v, sign) in c]))

            break

    assert solver.check(And([soln_sym[v] == soln[v][1] for (v, _) in c])) == sat
    assert solver.check(Or([soln_sym[v] != soln[v][1] for (v, _) in c])) == unsat

    return s

def part4(flag, start, end):
    flag = flag[start:end]

    constraints = "\n"
    node_idx = 0
    for (flag_idx, c) in enumerate(flag):
        # Generate a weighted graph with shortest path between A and B of length c
        n = 25
        m = 100
        while True:
            seed = random.randint(0, 1000000)
            G = nx.gnm_random_graph(n, m, seed=seed, directed=True)
            for (u, v) in G.edges():
                G[u][v]['weight'] = random.randint(1, 300)
            
            A = random.randint(0, n-1)
            B = A
            while B == A:
                B = random.randint(0, n-1)

            path = nx.shortest_path(G, A, B, weight='weight')
            path_weight = 0
            for i in range(len(path)-1):
                path_weight += G[path[i]][path[i+1]]['weight']
            if path_weight < c:
                continue
            
            # Now, reduce every weight in the path such that the path weight is exactly c
            required_reduction = path_weight - c
            for i in range(len(path)-1):
                cur_weight = G[path[i]][path[i+1]]['weight']
                reduction = min(cur_weight-random.randrange(10), required_reduction)
                cur_weight -= reduction
                required_reduction -= reduction
                G[path[i]][path[i+1]]['weight'] = cur_weight

            if required_reduction != 0:
                continue
            if nx.shortest_path(G, A, B, weight='weight') != path:
                continue

            # Output the graph
            constraints += f"ev {B+node_idx} {flag_idx}\n"
            constraints += f"ec {flag_idx+start} {A+node_idx}\n"

            # Output all edges and weights
            for (u, v) in G.edges():
                constraints += f"ee {u+node_idx} {v+node_idx} {G[u][v]['weight']}\n"
            
            node_idx += n
            break

    return constraints


with open("flag.txt", "wb") as f:
    f.write(FLAG)

with open("data", "w") as f:
    f.write(part1(FLAG, 0, 24))
    f.write(part2(FLAG, 24, 48))
    f.write(soduku_constraints)
    f.write(part4(FLAG, 48+81, len(FLAG)))
