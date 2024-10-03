extern crate datafrog;
use datafrog::{Iteration, Relation, PrefixFilter, ValueFilter, RelationLeaper};
use std::io::{stdin};

fn main() {
    let timer = ::std::time::Instant::now();

    let mut v_ac = Vec::new();
    let mut v_av = Vec::new();
    let mut v_bc = Vec::new();
    let mut v_bv = Vec::new();
    let mut v_cc = Vec::new();
    let mut v_cv = Vec::new();
    let mut v_ee = Vec::new();
    let mut v_ev = Vec::new();
    let mut v_ec = Vec::new();

    use std::fs::File;
    use std::io::{BufRead, BufReader};

    let filename = "data";
    let file = BufReader::new(File::open(filename).unwrap());
    for readline in file.lines() {
        let line = readline.expect("read error");
        if !line.is_empty() && !line.starts_with('#') {
            let mut elts = line[..].split_whitespace();
            let typ: &str = elts.next().unwrap();
            match typ {
                "ac" | "av" | "bv" | "ec" | "ev" => {
                    let a: usize = elts.next().unwrap().parse().expect("malformed a");
                    let b: usize = elts.next().unwrap().parse().expect("malformed b");
                    match typ {
                        "ac" => v_ac.push((a, b)),
                        "av" => v_av.push((a, b)),
                        "bv" => v_bv.push((a, b)),
                        "ec" => v_ec.push((a, b)),
                        "ev" => v_ev.push((a, b)),
                        unk => panic!("unknown type: {}", unk),
                    }
                }
                "bc" => {
                    let a: isize = elts.next().unwrap().parse().expect("malformed a");
                    let b: isize = elts.next().unwrap().parse().expect("malformed b");
                    let c: isize = elts.next().unwrap().parse().expect("malformed c");
                    v_bc.push((a, (b, c)));
                }
                "cc" | "cv" | "ee" => {
                    let a: usize = elts.next().unwrap().parse().expect("malformed a");
                    let b: usize = elts.next().unwrap().parse().expect("malformed b");
                    let c: usize = elts.next().unwrap().parse().expect("malformed c");
                    match typ {
                        "cc" => v_cc.push((a, (b, c))),
                        "cv" => v_cv.push((a, (b, c))),
                        "ee" => v_ee.push((a, (b, c))),
                        unk => panic!("unknown type {}", unk),
                    }
                }
                unk => panic!("unknown type: {}", unk),
            }
        }
    }

    println!("{:?}\tData loaded", timer.elapsed());


    print!("> ");
    let mut flag_str = String::new();
    stdin().read_line(&mut flag_str).unwrap();
    if flag_str.len() != 168 {
        panic!("bad flag length");
    }

    let flag_facts = Relation::from_iter(flag_str.trim_end().as_bytes().iter().cloned().enumerate());

    let mut iteration = Iteration::new();

    let checks = iteration.variable::<(usize, Option<bool>)>("checks");
    let z1 = iteration.variable::<(usize, usize)>("z1");
    z1.extend(flag_facts.iter().map(|&(i, _)| (i, 7)));
    let z2 = iteration.variable::<(usize, bool)>("z2");

    let ac: Relation<(usize, usize)> = Relation::from_vec(v_ac);
    let av: Relation<(usize, usize)> = Relation::from_vec(v_av);
    let bv: Relation<(usize, usize)> = Relation::from_vec(v_bv);
    let cv: Relation<(usize, (usize, usize))> = Relation::from_vec(v_cv);
    let cc: Relation<(usize, (usize, usize))> = Relation::from_vec(v_cc);

    let a1 = iteration.variable::<(usize, ())>("a1");
    let a2 = iteration.variable::<usize>("a2");
    let a3 = iteration.variable::<(usize, usize)>("a3");
    let a4 = iteration.variable::<(usize, ())>("a4");
    a4.insert(vec![(0, ())].into());

    let b1 = iteration.variable::<(isize, ())>("b1");
    let b2 = iteration.variable::<(isize, ())>("b2");
    let b3 = iteration.variable::<(isize, isize)>("b3");
    let b4 = iteration.variable::<(isize, (isize, isize))>("b4");
    b4.insert(v_bc.into());

    let c1 = iteration.variable::<(usize, (usize, usize))>("c1");
    c1.insert(cc.into());
    let c2 = iteration.variable::<(usize, (usize, usize))>("c2");
    let c3 = iteration.variable::<((usize, usize), usize)>("c3");
    let c4 = iteration.variable::<((usize, usize), usize)>("c4");
    let c5 = iteration.variable::<((usize, usize, usize), (usize, usize))>("c5");
    let c6 = iteration.variable::<(usize, (usize, usize))>("c6");
    c6.insert(cv.into());


    let e1 = iteration.variable::<(usize, usize)>("e1");
    let e2: Relation<(usize, (usize, usize))> = Relation::from_vec(v_ee);
    let e3: Relation<(usize, usize)> = Relation::from_vec(v_ev);
    let e4 = iteration.variable::<usize>("e4");
    let e5 = iteration.variable::<(usize, usize)>("e5");
    let e6 = iteration.variable::<(usize, ())>("e6");
    let e7 = iteration.variable::<(usize, usize)>("e7");
    e6.insert(vec![(0, ())].into());
    e7.insert(v_ec.into());

    while iteration.changed() {
        a1.from_join(&z2, &av, |&_, &b, &c| (c + !b as usize, ()));
        a2.from_join(&a1, &ac, |_, _, &cls| cls);
        a3.from_map(&a2, |&x| (x, x+1));
        a4.from_join(&a4, &a3, |_, _, &n| (n, ()));
        checks.from_map(&a4, |&(n, _)| (0, (n == ac.iter().map(|&(_, b)| b).max().unwrap()).then_some(true)));

        b4.from_map(&b4, |&(a, (b, c))| (b, (a, c)));
        b4.from_map(&b4, |&(a, (b, c))| (a, (c, b)));
        b2.from_map(&b1, |&(x, _)| (-x, ()));
        b1.from_map(&b2, |&(x, _)| (-x, ()));
        b3.from_join(&b2, &b4, |_, _, &x| x);
        b1.from_join(&b2, &b3, |_, _, &x| (x, ()));
        b1.from_join_filtered(&z2, &bv, |&_, &b, &c| b.then_some((c as isize, ())));
        b2.from_join_filtered(&z2, &bv, |&_, &b, &c| (!b).then_some((c as isize, ())));
        checks.from_join(&b1, &b2, |_, _, _| (1, Some(false)));
        checks.insert(vec![(1, Some(true))].into());

        c1.from_join_filtered(&c6, &flag_facts, |_, &(b, c), &a| (a >= 65 && a <= 73).then_some((b, (c, (a as usize) - 65))));
        c2.from_map(&c1, |&(a, (b, c))| (b, (a, c)));
        c3.from_map(&c1, |&(a, (b, c))| ((c, a), b));
        c4.from_map(&c2, |&(a, (b, c))| ((c, a), b));
        c5.from_map(&c1, |&(a, (b, c))| ((a/3, b/3, c), (a, b)));
        checks.from_join(&c3, &c3, |_, a, b| (2, (a != b).then_some(false)));
        checks.from_join(&c4, &c4, |_, a, b| (2, (a != b).then_some(false)));
        checks.from_join(&c5, &c5, |_, a, b| (2, (a != b).then_some(false)));
        checks.from_join(&c6, &flag_facts, |_, _, &a| (2, (a < 65 || a > 73).then_some(false)));
        checks.insert(vec![(2, Some(true))].into());


        e1.from_join(&e7, &flag_facts, |_, &a, &b| (a, b as usize));
        e1.from_join_filtered(&e1, &e2, |_, &a, &(b, c)| (a >= c).then_some((b, a.saturating_sub(c))));
        e4.from_join_filtered(&e1, &e3, |&_, &b, &c| (b == 0).then_some(c));
        checks.from_join(&e1, &e3, |_, &a, &_| (3, (a > 0).then_some(false)));
        e5.from_map(&e4, |&x| (x, x+1));
        e6.from_join(&e6, &e5, |_, _, &a| (a, ()));
        checks.from_map(&e6, |&(n, _)| (3, (n == e3.len()).then_some(true)));

        z1.from_map(&z1, |&(a, b)| (a, b.saturating_sub(1)));
        z2.from_join(&z1, &flag_facts, |&a, &b, &c| (a * 8 + b, ((c >> b) & 1) != 0));
    }

    let checks = checks.complete();
    let pass = (0..=3).all(|i| checks.contains(&(i, Some(true))) && !checks.contains(&(i, Some(false))));
    if pass {
        println!("Congratulations, the flag is {}", flag_str);
    } else {
        println!(":(");
    }
}

