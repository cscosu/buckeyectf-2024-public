
global flaginput := ""

logInput(key){
	global flaginput
	flaginput := flaginput . key
	flaginput := SubStr(flaginput,-28)
	checkInput()
}

checkInput(){
	global flaginput
	; ensure flag guess is 29 characters long
	if (StrLen(flaginput) != 29)
		return
	; ensure flag format is correct
	if (SubStr(flaginput, 1, 5) != "bctf{" or SubStr(flaginput,0) != "}")
		return
	; perform super-secret encryption algorithm
	encrypted_flag := [62,63,40,58,39,40,111,63,52,50,53,63,104,48,48,37,3,61,3,55,57,37,48,108,59,59,111,46,33]
	Loop 29 
	{
		if ((encrypted_flag[A_Index] ^ 92) != Asc(SubStr(flaginput,A_Index,1))) {
			MsgBox, You typed the wrong flag.
			return
		}
	}
	
	MsgBox, You typed the right flag!
}


; define logged characters
~a::logInput("a")
~b::logInput("b")
~c::logInput("c")
~d::logInput("d")
~e::logInput("e")
~f::logInput("f")
~g::logInput("g")
~h::logInput("h")
~i::logInput("i")
~j::logInput("j")
~k::logInput("k")
~l::logInput("l")
~m::logInput("m")
~n::logInput("n")
~o::logInput("o")
~p::logInput("p")
~q::logInput("q")
~r::logInput("r")
~s::logInput("s")
~t::logInput("t")
~u::logInput("u")
~v::logInput("v")
~w::logInput("w")
~x::logInput("x")
~y::logInput("y")
~z::logInput("z")
~0::logInput("0")
~1::logInput("1")
~2::logInput("2")
~3::logInput("3")
~4::logInput("4")
~5::logInput("5")
~6::logInput("6")
~7::logInput("7")
~8::logInput("8")
~9::logInput("9")
~_::logInput("_")
~{::logInput("{")
~}::logInput("}")