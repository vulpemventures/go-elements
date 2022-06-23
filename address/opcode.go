package address

import "github.com/btcsuite/btcd/txscript"

// elements tapscript opcodes
const (
	OP_SHA256INITIALIZE = 0xc4
	OP_SHA256UPDATE     = 0xc5
	OP_SHA256FINALIZE   = 0xc6

	// Introspection opcodes
	// inputs
	OP_INSPECTINPUTOUTPOINT     = 0xc7
	OP_INSPECTINPUTASSET        = 0xc8
	OP_INSPECTINPUTVALUE        = 0xc9
	OP_INSPECTINPUTSCRIPTPUBKEY = 0xca
	OP_INSPECTINPUTSEQUENCE     = 0xcb
	OP_INSPECTINPUTISSUANCE     = 0xcc
	OP_PUSHCURRENTINPUTINDEX    = 0xcd

	// outputs
	OP_INSPECTOUTPUTASSET        = 0xce
	OP_INSPECTOUTPUTVALUE        = 0xcf
	OP_INSPECTOUTPUTNONCE        = 0xd0
	OP_INSPECTOUTPUTSCRIPTPUBKEY = 0xd1

	// transaction
	OP_INSPECTVERSION    = 0xd2
	OP_INSPECTLOCKTIME   = 0xd3
	OP_INSPECTNUMINPUTS  = 0xd4
	OP_INSPECTNUMOUTPUTS = 0xd5
	OP_TXWEIGHT          = 0xd6

	// Arithmetic opcodes
	OP_ADD64                = 0xd7
	OP_SUB64                = 0xd8
	OP_MUL64                = 0xd9
	OP_DIV64                = 0xda
	OP_NEG64                = 0xdb
	OP_LESSTHAN64           = 0xdc
	OP_LESSTHANOREQUAL64    = 0xdd
	OP_GREATERTHAN64        = 0xde
	OP_GREATERTHANOREQUAL64 = 0xdf

	// Conversion opcodes
	OP_SCRIPTNUMTOLE64 = 0xe0
	OP_LE64TOSCRIPTNUM = 0xe1
	OP_LE32TOLE64      = 0xe2
)

// opcodeArray holds details about all possible opcodes such as how many bytes
// the Opcode and any associated Data should take, its human-readable Name, and
// the handler function.
var opcodeArray = [256]Opcode{
	// Data push opcodes.
	// Data push opcodes.
	txscript.OP_FALSE:     {txscript.OP_FALSE, "OP_0", 1},
	txscript.OP_DATA_1:    {txscript.OP_DATA_1, "OP_DATA_1", 2},
	txscript.OP_DATA_2:    {txscript.OP_DATA_2, "OP_DATA_2", 3},
	txscript.OP_DATA_3:    {txscript.OP_DATA_3, "OP_DATA_3", 4},
	txscript.OP_DATA_4:    {txscript.OP_DATA_4, "OP_DATA_4", 5},
	txscript.OP_DATA_5:    {txscript.OP_DATA_5, "OP_DATA_5", 6},
	txscript.OP_DATA_6:    {txscript.OP_DATA_6, "OP_DATA_6", 7},
	txscript.OP_DATA_7:    {txscript.OP_DATA_7, "OP_DATA_7", 8},
	txscript.OP_DATA_8:    {txscript.OP_DATA_8, "OP_DATA_8", 9},
	txscript.OP_DATA_9:    {txscript.OP_DATA_9, "OP_DATA_9", 10},
	txscript.OP_DATA_10:   {txscript.OP_DATA_10, "OP_DATA_10", 11},
	txscript.OP_DATA_11:   {txscript.OP_DATA_11, "OP_DATA_11", 12},
	txscript.OP_DATA_12:   {txscript.OP_DATA_12, "OP_DATA_12", 13},
	txscript.OP_DATA_13:   {txscript.OP_DATA_13, "OP_DATA_13", 14},
	txscript.OP_DATA_14:   {txscript.OP_DATA_14, "OP_DATA_14", 15},
	txscript.OP_DATA_15:   {txscript.OP_DATA_15, "OP_DATA_15", 16},
	txscript.OP_DATA_16:   {txscript.OP_DATA_16, "OP_DATA_16", 17},
	txscript.OP_DATA_17:   {txscript.OP_DATA_17, "OP_DATA_17", 18},
	txscript.OP_DATA_18:   {txscript.OP_DATA_18, "OP_DATA_18", 19},
	txscript.OP_DATA_19:   {txscript.OP_DATA_19, "OP_DATA_19", 20},
	txscript.OP_DATA_20:   {txscript.OP_DATA_20, "OP_DATA_20", 21},
	txscript.OP_DATA_21:   {txscript.OP_DATA_21, "OP_DATA_21", 22},
	txscript.OP_DATA_22:   {txscript.OP_DATA_22, "OP_DATA_22", 23},
	txscript.OP_DATA_23:   {txscript.OP_DATA_23, "OP_DATA_23", 24},
	txscript.OP_DATA_24:   {txscript.OP_DATA_24, "OP_DATA_24", 25},
	txscript.OP_DATA_25:   {txscript.OP_DATA_25, "OP_DATA_25", 26},
	txscript.OP_DATA_26:   {txscript.OP_DATA_26, "OP_DATA_26", 27},
	txscript.OP_DATA_27:   {txscript.OP_DATA_27, "OP_DATA_27", 28},
	txscript.OP_DATA_28:   {txscript.OP_DATA_28, "OP_DATA_28", 29},
	txscript.OP_DATA_29:   {txscript.OP_DATA_29, "OP_DATA_29", 30},
	txscript.OP_DATA_30:   {txscript.OP_DATA_30, "OP_DATA_30", 31},
	txscript.OP_DATA_31:   {txscript.OP_DATA_31, "OP_DATA_31", 32},
	txscript.OP_DATA_32:   {txscript.OP_DATA_32, "OP_DATA_32", 33},
	txscript.OP_DATA_33:   {txscript.OP_DATA_33, "OP_DATA_33", 34},
	txscript.OP_DATA_34:   {txscript.OP_DATA_34, "OP_DATA_34", 35},
	txscript.OP_DATA_35:   {txscript.OP_DATA_35, "OP_DATA_35", 36},
	txscript.OP_DATA_36:   {txscript.OP_DATA_36, "OP_DATA_36", 37},
	txscript.OP_DATA_37:   {txscript.OP_DATA_37, "OP_DATA_37", 38},
	txscript.OP_DATA_38:   {txscript.OP_DATA_38, "OP_DATA_38", 39},
	txscript.OP_DATA_39:   {txscript.OP_DATA_39, "OP_DATA_39", 40},
	txscript.OP_DATA_40:   {txscript.OP_DATA_40, "OP_DATA_40", 41},
	txscript.OP_DATA_41:   {txscript.OP_DATA_41, "OP_DATA_41", 42},
	txscript.OP_DATA_42:   {txscript.OP_DATA_42, "OP_DATA_42", 43},
	txscript.OP_DATA_43:   {txscript.OP_DATA_43, "OP_DATA_43", 44},
	txscript.OP_DATA_44:   {txscript.OP_DATA_44, "OP_DATA_44", 45},
	txscript.OP_DATA_45:   {txscript.OP_DATA_45, "OP_DATA_45", 46},
	txscript.OP_DATA_46:   {txscript.OP_DATA_46, "OP_DATA_46", 47},
	txscript.OP_DATA_47:   {txscript.OP_DATA_47, "OP_DATA_47", 48},
	txscript.OP_DATA_48:   {txscript.OP_DATA_48, "OP_DATA_48", 49},
	txscript.OP_DATA_49:   {txscript.OP_DATA_49, "OP_DATA_49", 50},
	txscript.OP_DATA_50:   {txscript.OP_DATA_50, "OP_DATA_50", 51},
	txscript.OP_DATA_51:   {txscript.OP_DATA_51, "OP_DATA_51", 52},
	txscript.OP_DATA_52:   {txscript.OP_DATA_52, "OP_DATA_52", 53},
	txscript.OP_DATA_53:   {txscript.OP_DATA_53, "OP_DATA_53", 54},
	txscript.OP_DATA_54:   {txscript.OP_DATA_54, "OP_DATA_54", 55},
	txscript.OP_DATA_55:   {txscript.OP_DATA_55, "OP_DATA_55", 56},
	txscript.OP_DATA_56:   {txscript.OP_DATA_56, "OP_DATA_56", 57},
	txscript.OP_DATA_57:   {txscript.OP_DATA_57, "OP_DATA_57", 58},
	txscript.OP_DATA_58:   {txscript.OP_DATA_58, "OP_DATA_58", 59},
	txscript.OP_DATA_59:   {txscript.OP_DATA_59, "OP_DATA_59", 60},
	txscript.OP_DATA_60:   {txscript.OP_DATA_60, "OP_DATA_60", 61},
	txscript.OP_DATA_61:   {txscript.OP_DATA_61, "OP_DATA_61", 62},
	txscript.OP_DATA_62:   {txscript.OP_DATA_62, "OP_DATA_62", 63},
	txscript.OP_DATA_63:   {txscript.OP_DATA_63, "OP_DATA_63", 64},
	txscript.OP_DATA_64:   {txscript.OP_DATA_64, "OP_DATA_64", 65},
	txscript.OP_DATA_65:   {txscript.OP_DATA_65, "OP_DATA_65", 66},
	txscript.OP_DATA_66:   {txscript.OP_DATA_66, "OP_DATA_66", 67},
	txscript.OP_DATA_67:   {txscript.OP_DATA_67, "OP_DATA_67", 68},
	txscript.OP_DATA_68:   {txscript.OP_DATA_68, "OP_DATA_68", 69},
	txscript.OP_DATA_69:   {txscript.OP_DATA_69, "OP_DATA_69", 70},
	txscript.OP_DATA_70:   {txscript.OP_DATA_70, "OP_DATA_70", 71},
	txscript.OP_DATA_71:   {txscript.OP_DATA_71, "OP_DATA_71", 72},
	txscript.OP_DATA_72:   {txscript.OP_DATA_72, "OP_DATA_72", 73},
	txscript.OP_DATA_73:   {txscript.OP_DATA_73, "OP_DATA_73", 74},
	txscript.OP_DATA_74:   {txscript.OP_DATA_74, "OP_DATA_74", 75},
	txscript.OP_DATA_75:   {txscript.OP_DATA_75, "OP_DATA_75", 76},
	txscript.OP_PUSHDATA1: {txscript.OP_PUSHDATA1, "OP_PUSHDATA1", -1},
	txscript.OP_PUSHDATA2: {txscript.OP_PUSHDATA2, "OP_PUSHDATA2", -2},
	txscript.OP_PUSHDATA4: {txscript.OP_PUSHDATA4, "OP_PUSHDATA4", -4},
	txscript.OP_1NEGATE:   {txscript.OP_1NEGATE, "OP_1NEGATE", 1},
	txscript.OP_RESERVED:  {txscript.OP_RESERVED, "OP_RESERVED", 1},
	txscript.OP_TRUE:      {txscript.OP_TRUE, "OP_1", 1},
	txscript.OP_2:         {txscript.OP_2, "OP_2", 1},
	txscript.OP_3:         {txscript.OP_3, "OP_3", 1},
	txscript.OP_4:         {txscript.OP_4, "OP_4", 1},
	txscript.OP_5:         {txscript.OP_5, "OP_5", 1},
	txscript.OP_6:         {txscript.OP_6, "OP_6", 1},
	txscript.OP_7:         {txscript.OP_7, "OP_7", 1},
	txscript.OP_8:         {txscript.OP_8, "OP_8", 1},
	txscript.OP_9:         {txscript.OP_9, "OP_9", 1},
	txscript.OP_10:        {txscript.OP_10, "OP_10", 1},
	txscript.OP_11:        {txscript.OP_11, "OP_11", 1},
	txscript.OP_12:        {txscript.OP_12, "OP_12", 1},
	txscript.OP_13:        {txscript.OP_13, "OP_13", 1},
	txscript.OP_14:        {txscript.OP_14, "OP_14", 1},
	txscript.OP_15:        {txscript.OP_15, "OP_15", 1},
	txscript.OP_16:        {txscript.OP_16, "OP_16", 1},

	// Control opcodes.
	txscript.OP_NOP:                 {txscript.OP_NOP, "OP_NOP", 1},
	txscript.OP_VER:                 {txscript.OP_VER, "OP_VER", 1},
	txscript.OP_IF:                  {txscript.OP_IF, "OP_IF", 1},
	txscript.OP_NOTIF:               {txscript.OP_NOTIF, "OP_NOTIF", 1},
	txscript.OP_VERIF:               {txscript.OP_VERIF, "OP_VERIF", 1},
	txscript.OP_VERNOTIF:            {txscript.OP_VERNOTIF, "OP_VERNOTIF", 1},
	txscript.OP_ELSE:                {txscript.OP_ELSE, "OP_ELSE", 1},
	txscript.OP_ENDIF:               {txscript.OP_ENDIF, "OP_ENDIF", 1},
	txscript.OP_VERIFY:              {txscript.OP_VERIFY, "OP_VERIFY", 1},
	txscript.OP_RETURN:              {txscript.OP_RETURN, "OP_RETURN", 1},
	txscript.OP_CHECKLOCKTIMEVERIFY: {txscript.OP_CHECKLOCKTIMEVERIFY, "OP_CHECKLOCKTIMEVERIFY", 1},
	txscript.OP_CHECKSEQUENCEVERIFY: {txscript.OP_CHECKSEQUENCEVERIFY, "OP_CHECKSEQUENCEVERIFY", 1},

	// Stack opcodes.
	txscript.OP_TOALTSTACK:   {txscript.OP_TOALTSTACK, "OP_TOALTSTACK", 1},
	txscript.OP_FROMALTSTACK: {txscript.OP_FROMALTSTACK, "OP_FROMALTSTACK", 1},
	txscript.OP_2DROP:        {txscript.OP_2DROP, "OP_2DROP", 1},
	txscript.OP_2DUP:         {txscript.OP_2DUP, "OP_2DUP", 1},
	txscript.OP_3DUP:         {txscript.OP_3DUP, "OP_3DUP", 1},
	txscript.OP_2OVER:        {txscript.OP_2OVER, "OP_2OVER", 1},
	txscript.OP_2ROT:         {txscript.OP_2ROT, "OP_2ROT", 1},
	txscript.OP_2SWAP:        {txscript.OP_2SWAP, "OP_2SWAP", 1},
	txscript.OP_IFDUP:        {txscript.OP_IFDUP, "OP_IFDUP", 1},
	txscript.OP_DEPTH:        {txscript.OP_DEPTH, "OP_DEPTH", 1},
	txscript.OP_DROP:         {txscript.OP_DROP, "OP_DROP", 1},
	txscript.OP_DUP:          {txscript.OP_DUP, "OP_DUP", 1},
	txscript.OP_NIP:          {txscript.OP_NIP, "OP_NIP", 1},
	txscript.OP_OVER:         {txscript.OP_OVER, "OP_OVER", 1},
	txscript.OP_PICK:         {txscript.OP_PICK, "OP_PICK", 1},
	txscript.OP_ROLL:         {txscript.OP_ROLL, "OP_ROLL", 1},
	txscript.OP_ROT:          {txscript.OP_ROT, "OP_ROT", 1},
	txscript.OP_SWAP:         {txscript.OP_SWAP, "OP_SWAP", 1},
	txscript.OP_TUCK:         {txscript.OP_TUCK, "OP_TUCK", 1},

	// Splice opcodes.
	txscript.OP_CAT:    {txscript.OP_CAT, "OP_CAT", 1},
	txscript.OP_SUBSTR: {txscript.OP_SUBSTR, "OP_SUBSTR", 1},
	txscript.OP_LEFT:   {txscript.OP_LEFT, "OP_LEFT", 1},
	txscript.OP_RIGHT:  {txscript.OP_RIGHT, "OP_RIGHT", 1},
	txscript.OP_SIZE:   {txscript.OP_SIZE, "OP_SIZE", 1},

	// Bitwise logic opcodes.
	txscript.OP_INVERT:      {txscript.OP_INVERT, "OP_INVERT", 1},
	txscript.OP_AND:         {txscript.OP_AND, "OP_AND", 1},
	txscript.OP_OR:          {txscript.OP_OR, "OP_OR", 1},
	txscript.OP_XOR:         {txscript.OP_XOR, "OP_XOR", 1},
	txscript.OP_EQUAL:       {txscript.OP_EQUAL, "OP_EQUAL", 1},
	txscript.OP_EQUALVERIFY: {txscript.OP_EQUALVERIFY, "OP_EQUALVERIFY", 1},
	txscript.OP_RESERVED1:   {txscript.OP_RESERVED1, "OP_RESERVED1", 1},
	txscript.OP_RESERVED2:   {txscript.OP_RESERVED2, "OP_RESERVED2", 1},

	// Numeric related opcodes.
	txscript.OP_1ADD:               {txscript.OP_1ADD, "OP_1ADD", 1},
	txscript.OP_1SUB:               {txscript.OP_1SUB, "OP_1SUB", 1},
	txscript.OP_2MUL:               {txscript.OP_2MUL, "OP_2MUL", 1},
	txscript.OP_2DIV:               {txscript.OP_2DIV, "OP_2DIV", 1},
	txscript.OP_NEGATE:             {txscript.OP_NEGATE, "OP_NEGATE", 1},
	txscript.OP_ABS:                {txscript.OP_ABS, "OP_ABS", 1},
	txscript.OP_NOT:                {txscript.OP_NOT, "OP_NOT", 1},
	txscript.OP_0NOTEQUAL:          {txscript.OP_0NOTEQUAL, "OP_0NOTEQUAL", 1},
	txscript.OP_ADD:                {txscript.OP_ADD, "OP_ADD", 1},
	txscript.OP_SUB:                {txscript.OP_SUB, "OP_SUB", 1},
	txscript.OP_MUL:                {txscript.OP_MUL, "OP_MUL", 1},
	txscript.OP_DIV:                {txscript.OP_DIV, "OP_DIV", 1},
	txscript.OP_MOD:                {txscript.OP_MOD, "OP_MOD", 1},
	txscript.OP_LSHIFT:             {txscript.OP_LSHIFT, "OP_LSHIFT", 1},
	txscript.OP_RSHIFT:             {txscript.OP_RSHIFT, "OP_RSHIFT", 1},
	txscript.OP_BOOLAND:            {txscript.OP_BOOLAND, "OP_BOOLAND", 1},
	txscript.OP_BOOLOR:             {txscript.OP_BOOLOR, "OP_BOOLOR", 1},
	txscript.OP_NUMEQUAL:           {txscript.OP_NUMEQUAL, "OP_NUMEQUAL", 1},
	txscript.OP_NUMEQUALVERIFY:     {txscript.OP_NUMEQUALVERIFY, "OP_NUMEQUALVERIFY", 1},
	txscript.OP_NUMNOTEQUAL:        {txscript.OP_NUMNOTEQUAL, "OP_NUMNOTEQUAL", 1},
	txscript.OP_LESSTHAN:           {txscript.OP_LESSTHAN, "OP_LESSTHAN", 1},
	txscript.OP_GREATERTHAN:        {txscript.OP_GREATERTHAN, "OP_GREATERTHAN", 1},
	txscript.OP_LESSTHANOREQUAL:    {txscript.OP_LESSTHANOREQUAL, "OP_LESSTHANOREQUAL", 1},
	txscript.OP_GREATERTHANOREQUAL: {txscript.OP_GREATERTHANOREQUAL, "OP_GREATERTHANOREQUAL", 1},
	txscript.OP_MIN:                {txscript.OP_MIN, "OP_MIN", 1},
	txscript.OP_MAX:                {txscript.OP_MAX, "OP_MAX", 1},
	txscript.OP_WITHIN:             {txscript.OP_WITHIN, "OP_WITHIN", 1},

	// Crypto opcodes.
	txscript.OP_RIPEMD160:           {txscript.OP_RIPEMD160, "OP_RIPEMD160", 1},
	txscript.OP_SHA1:                {txscript.OP_SHA1, "OP_SHA1", 1},
	txscript.OP_SHA256:              {txscript.OP_SHA256, "OP_SHA256", 1},
	txscript.OP_HASH160:             {txscript.OP_HASH160, "OP_HASH160", 1},
	txscript.OP_HASH256:             {txscript.OP_HASH256, "OP_HASH256", 1},
	txscript.OP_CODESEPARATOR:       {txscript.OP_CODESEPARATOR, "OP_CODESEPARATOR", 1},
	txscript.OP_CHECKSIG:            {txscript.OP_CHECKSIG, "OP_CHECKSIG", 1},
	txscript.OP_CHECKSIGVERIFY:      {txscript.OP_CHECKSIGVERIFY, "OP_CHECKSIGVERIFY", 1},
	txscript.OP_CHECKMULTISIG:       {txscript.OP_CHECKMULTISIG, "OP_CHECKMULTISIG", 1},
	txscript.OP_CHECKMULTISIGVERIFY: {txscript.OP_CHECKMULTISIGVERIFY, "OP_CHECKMULTISIGVERIFY", 1},

	// Reserved opcodes.
	txscript.OP_NOP1:  {txscript.OP_NOP1, "OP_NOP1", 1},
	txscript.OP_NOP4:  {txscript.OP_NOP4, "OP_NOP4", 1},
	txscript.OP_NOP5:  {txscript.OP_NOP5, "OP_NOP5", 1},
	txscript.OP_NOP6:  {txscript.OP_NOP6, "OP_NOP6", 1},
	txscript.OP_NOP7:  {txscript.OP_NOP7, "OP_NOP7", 1},
	txscript.OP_NOP8:  {txscript.OP_NOP8, "OP_NOP8", 1},
	txscript.OP_NOP9:  {txscript.OP_NOP9, "OP_NOP9", 1},
	txscript.OP_NOP10: {txscript.OP_NOP10, "OP_NOP10", 1},

	// taproot update
	txscript.OP_CHECKSIGADD: {txscript.OP_CHECKSIGADD, "OP_CHECKSIGADD", 1},

	// Undefined opcodes.
	txscript.OP_UNKNOWN187: {txscript.OP_UNKNOWN187, "OP_UNKNOWN187", 1},
	txscript.OP_UNKNOWN188: {txscript.OP_UNKNOWN188, "OP_UNKNOWN188", 1},
	txscript.OP_UNKNOWN189: {txscript.OP_UNKNOWN189, "OP_UNKNOWN189", 1},
	txscript.OP_UNKNOWN190: {txscript.OP_UNKNOWN190, "OP_UNKNOWN190", 1},
	txscript.OP_UNKNOWN191: {txscript.OP_UNKNOWN191, "OP_UNKNOWN191", 1},
	txscript.OP_UNKNOWN192: {txscript.OP_UNKNOWN192, "OP_UNKNOWN192", 1},
	txscript.OP_UNKNOWN193: {txscript.OP_UNKNOWN193, "OP_UNKNOWN193", 1},
	txscript.OP_UNKNOWN194: {txscript.OP_UNKNOWN194, "OP_UNKNOWN194", 1},
	txscript.OP_UNKNOWN195: {txscript.OP_UNKNOWN195, "OP_UNKNOWN195", 1},
	txscript.OP_UNKNOWN196: {txscript.OP_UNKNOWN196, "OP_UNKNOWN196", 1},
	txscript.OP_UNKNOWN197: {txscript.OP_UNKNOWN197, "OP_UNKNOWN197", 1},
	txscript.OP_UNKNOWN198: {txscript.OP_UNKNOWN198, "OP_UNKNOWN198", 1},
	txscript.OP_UNKNOWN199: {txscript.OP_UNKNOWN199, "OP_UNKNOWN199", 1},
	txscript.OP_UNKNOWN200: {txscript.OP_UNKNOWN200, "OP_UNKNOWN200", 1},
	txscript.OP_UNKNOWN201: {txscript.OP_UNKNOWN201, "OP_UNKNOWN201", 1},
	txscript.OP_UNKNOWN202: {txscript.OP_UNKNOWN202, "OP_UNKNOWN202", 1},
	txscript.OP_UNKNOWN203: {txscript.OP_UNKNOWN203, "OP_UNKNOWN203", 1},
	txscript.OP_UNKNOWN204: {txscript.OP_UNKNOWN204, "OP_UNKNOWN204", 1},
	txscript.OP_UNKNOWN205: {txscript.OP_UNKNOWN205, "OP_UNKNOWN205", 1},
	txscript.OP_UNKNOWN206: {txscript.OP_UNKNOWN206, "OP_UNKNOWN206", 1},
	txscript.OP_UNKNOWN207: {txscript.OP_UNKNOWN207, "OP_UNKNOWN207", 1},
	txscript.OP_UNKNOWN208: {txscript.OP_UNKNOWN208, "OP_UNKNOWN208", 1},
	txscript.OP_UNKNOWN209: {txscript.OP_UNKNOWN209, "OP_UNKNOWN209", 1},
	txscript.OP_UNKNOWN210: {txscript.OP_UNKNOWN210, "OP_UNKNOWN210", 1},
	txscript.OP_UNKNOWN211: {txscript.OP_UNKNOWN211, "OP_UNKNOWN211", 1},
	txscript.OP_UNKNOWN212: {txscript.OP_UNKNOWN212, "OP_UNKNOWN212", 1},
	txscript.OP_UNKNOWN213: {txscript.OP_UNKNOWN213, "OP_UNKNOWN213", 1},
	txscript.OP_UNKNOWN214: {txscript.OP_UNKNOWN214, "OP_UNKNOWN214", 1},
	txscript.OP_UNKNOWN215: {txscript.OP_UNKNOWN215, "OP_UNKNOWN215", 1},
	txscript.OP_UNKNOWN216: {txscript.OP_UNKNOWN216, "OP_UNKNOWN216", 1},
	txscript.OP_UNKNOWN217: {txscript.OP_UNKNOWN217, "OP_UNKNOWN217", 1},
	txscript.OP_UNKNOWN218: {txscript.OP_UNKNOWN218, "OP_UNKNOWN218", 1},
	txscript.OP_UNKNOWN219: {txscript.OP_UNKNOWN219, "OP_UNKNOWN219", 1},
	txscript.OP_UNKNOWN220: {txscript.OP_UNKNOWN220, "OP_UNKNOWN220", 1},
	txscript.OP_UNKNOWN221: {txscript.OP_UNKNOWN221, "OP_UNKNOWN221", 1},
	txscript.OP_UNKNOWN222: {txscript.OP_UNKNOWN222, "OP_UNKNOWN222", 1},
	txscript.OP_UNKNOWN223: {txscript.OP_UNKNOWN223, "OP_UNKNOWN223", 1},
	txscript.OP_UNKNOWN224: {txscript.OP_UNKNOWN224, "OP_UNKNOWN224", 1},
	txscript.OP_UNKNOWN225: {txscript.OP_UNKNOWN225, "OP_UNKNOWN225", 1},
	txscript.OP_UNKNOWN226: {txscript.OP_UNKNOWN226, "OP_UNKNOWN226", 1},
	txscript.OP_UNKNOWN227: {txscript.OP_UNKNOWN227, "OP_UNKNOWN227", 1},
	txscript.OP_UNKNOWN228: {txscript.OP_UNKNOWN228, "OP_UNKNOWN228", 1},
	txscript.OP_UNKNOWN229: {txscript.OP_UNKNOWN229, "OP_UNKNOWN229", 1},
	txscript.OP_UNKNOWN230: {txscript.OP_UNKNOWN230, "OP_UNKNOWN230", 1},
	txscript.OP_UNKNOWN231: {txscript.OP_UNKNOWN231, "OP_UNKNOWN231", 1},
	txscript.OP_UNKNOWN232: {txscript.OP_UNKNOWN232, "OP_UNKNOWN232", 1},
	txscript.OP_UNKNOWN233: {txscript.OP_UNKNOWN233, "OP_UNKNOWN233", 1},
	txscript.OP_UNKNOWN234: {txscript.OP_UNKNOWN234, "OP_UNKNOWN234", 1},
	txscript.OP_UNKNOWN235: {txscript.OP_UNKNOWN235, "OP_UNKNOWN235", 1},
	txscript.OP_UNKNOWN236: {txscript.OP_UNKNOWN236, "OP_UNKNOWN236", 1},
	txscript.OP_UNKNOWN237: {txscript.OP_UNKNOWN237, "OP_UNKNOWN237", 1},
	txscript.OP_UNKNOWN238: {txscript.OP_UNKNOWN238, "OP_UNKNOWN238", 1},
	txscript.OP_UNKNOWN239: {txscript.OP_UNKNOWN239, "OP_UNKNOWN239", 1},
	txscript.OP_UNKNOWN240: {txscript.OP_UNKNOWN240, "OP_UNKNOWN240", 1},
	txscript.OP_UNKNOWN241: {txscript.OP_UNKNOWN241, "OP_UNKNOWN241", 1},
	txscript.OP_UNKNOWN242: {txscript.OP_UNKNOWN242, "OP_UNKNOWN242", 1},
	txscript.OP_UNKNOWN243: {txscript.OP_UNKNOWN243, "OP_UNKNOWN243", 1},
	txscript.OP_UNKNOWN244: {txscript.OP_UNKNOWN244, "OP_UNKNOWN244", 1},
	txscript.OP_UNKNOWN245: {txscript.OP_UNKNOWN245, "OP_UNKNOWN245", 1},
	txscript.OP_UNKNOWN246: {txscript.OP_UNKNOWN246, "OP_UNKNOWN246", 1},
	txscript.OP_UNKNOWN247: {txscript.OP_UNKNOWN247, "OP_UNKNOWN247", 1},
	txscript.OP_UNKNOWN248: {txscript.OP_UNKNOWN248, "OP_UNKNOWN248", 1},
	txscript.OP_UNKNOWN249: {txscript.OP_UNKNOWN249, "OP_UNKNOWN249", 1},

	// Bitcoin Core internal use Opcode.  Defined here for completeness.
	txscript.OP_SMALLINTEGER: {txscript.OP_SMALLINTEGER, "OP_SMALLINTEGER", 1},
	txscript.OP_PUBKEYS:      {txscript.OP_PUBKEYS, "OP_PUBKEYS", 1},
	txscript.OP_UNKNOWN252:   {txscript.OP_UNKNOWN252, "OP_UNKNOWN252", 1},
	txscript.OP_PUBKEYHASH:   {txscript.OP_PUBKEYHASH, "OP_PUBKEYHASH", 1},
	txscript.OP_PUBKEY:       {txscript.OP_PUBKEY, "OP_PUBKEY", 1},

	txscript.OP_INVALIDOPCODE: {txscript.OP_INVALIDOPCODE, "OP_INVALIDOPCODE", 1},
}

// ParsedOpcode represents an Opcode that has been parsed and includes any
// potential Data associated with it.
type ParsedOpcode struct {
	Opcode *Opcode
	Data   []byte
}

// An Opcode defines the information related to a txscript Opcode.  opfunc, if
// present, is the function to call to perform the Opcode on the script.  The
// current script is passed in as a slice with the first member being the Opcode
// itself.
type Opcode struct {
	Value  byte
	Name   string
	Length int
}
