package abi

// x86_64 mnemonic constants used across abi analyzers
const (
	mnemonicCall = "call"
	mnemonicRet  = "ret"
	mnemonicRetn = "retn"
	mnemonicPush = "push"
	mnemonicPop  = "pop"
	mnemonicMov  = "mov"
	mnemonicSub  = "sub"
	mnemonicAdd  = "add"
	mnemonicAnd  = "and"
	mnemonicTest = "test"
	mnemonicCmp  = "cmp"
)

// x86_64 register name constants used across abi analyzers
const (
	regRax  = "rax"
	regRbx  = "rbx"
	regRcx  = "rcx"
	regRdx  = "rdx"
	regRsi  = "rsi"
	regRdi  = "rdi"
	regRbp  = "rbp"
	regRsp  = "rsp"
	regR10  = "r10"
	regR11  = "r11"
	regR12  = "r12"
	regR13  = "r13"
	regR14  = "r14"
	regR15  = "r15"
	regXmm0 = "xmm0"
	regXmm1 = "xmm1"
	regXmm2 = "xmm2"
	regXmm3 = "xmm3"
	regXmm4 = "xmm4"
	regXmm5 = "xmm5"
	regXmm6 = "xmm6"
	regXmm7 = "xmm7"
)
