package signatures

import (
	"sort"

	binfmt "github.com/zarazaex69/sedec/pkg/binary"
)

// confidenceThreshold is the minimum score to include a result.
const confidenceThreshold = 0.10

// maxCandidates is the maximum number of results returned per query.
const maxCandidates = 16

// MatchSignatures matches a function against all signatures in the database
// and returns candidates ranked by confidence score (highest first).
//
// the confidence score combines:
//   - byte-level Jaccard similarity of the masked fingerprint (weight 0.55)
//   - CFG structural similarity (weight 0.35)
//   - name/symbol hint from the ground-truth database (weight 0.10)
//
// when multiple signatures share the same name (collision), all are returned
// so the caller can inspect the full candidate set (req 16.13).
//
// returns an empty slice (not nil) when no candidates exceed the threshold.
func MatchSignatures(input *MatchInput, db *SignatureDB) []MatchResult {
	if db == nil || db.Size() == 0 {
		return []MatchResult{}
	}

	// compute fingerprint and CFG hash for the query function
	var queryFP *FunctionFingerprint
	if len(input.Instructions) > 0 {
		queryFP = ComputeFingerprint(input.Instructions, 0)
	}

	var queryCFGHash *CFGHash
	if input.FunctionCFG != nil {
		queryCFGHash = ComputeCFGHash(input.FunctionCFG)
	}

	// resolve name hint from ground-truth database
	nameHint := ""
	if input.GroundTruth != nil {
		// binfmt.Address and disasm.Address are both uint64 aliases; explicit cast required
		binfmtAddr := binfmt.Address(input.Address)
		if name, ok := input.GroundTruth.SymbolsByAddress[binfmtAddr]; ok {
			nameHint = name
		}
	}

	results := make([]MatchResult, 0, 32)

	for _, sig := range db.Signatures {
		mr := scoreSig(sig, queryFP, queryCFGHash, nameHint, defaultWeights)
		if mr.Confidence >= confidenceThreshold {
			results = append(results, mr)
		}
	}

	// sort by confidence descending, then by name for determinism
	sort.Slice(results, func(i, j int) bool {
		if results[i].Confidence != results[j].Confidence {
			return results[i].Confidence > results[j].Confidence
		}
		return results[i].Signature.Name < results[j].Signature.Name
	})

	// cap at maxCandidates
	if len(results) > maxCandidates {
		results = results[:maxCandidates]
	}

	return results
}

// scoreSig computes the MatchResult for a single signature against the query.
func scoreSig(
	sig *Signature,
	queryFP *FunctionFingerprint,
	queryCFGHash *CFGHash,
	nameHint string,
	w matchWeights,
) MatchResult {
	byteSim := computeByteSimilarity(queryFP, sig.Fingerprint)
	cfgSim := computeCFGSimilarity(queryCFGHash, sig.CFGHash)
	nameSim := computeNameSimilarity(nameHint, sig.Name)

	confidence := w.byteWeight*byteSim + w.cfgWeight*cfgSim + w.nameWeight*nameSim

	// clamp to [0, 1]
	if confidence > 1.0 {
		confidence = 1.0
	}
	if confidence < 0.0 {
		confidence = 0.0
	}

	return MatchResult{
		Signature:      sig,
		Confidence:     confidence,
		ByteSimilarity: byteSim,
		CFGSimilarity:  cfgSim,
		NameHint:       nameHint,
	}
}

// computeByteSimilarity returns the Jaccard similarity of two fingerprints.
// returns 0.5 (neutral) when either fingerprint is nil or empty, so that
// the CFG component can still contribute to the overall score.
func computeByteSimilarity(a, b *FunctionFingerprint) float64 {
	if a == nil || b == nil {
		return 0.5
	}
	if len(a.Pattern) == 0 || len(b.Pattern) == 0 {
		return 0.5
	}
	return FingerprintSimilarity(a, b)
}

// computeCFGSimilarity returns the structural similarity of two CFG hashes.
// returns 0.5 (neutral) when either hash is nil.
func computeCFGSimilarity(a, b *CFGHash) float64 {
	if a == nil || b == nil {
		return 0.5
	}
	return CFGHashSimilarity(a, b)
}

// computeNameSimilarity returns 1.0 if the name hint matches the signature
// name exactly, 0.0 otherwise.
func computeNameSimilarity(hint, sigName string) float64 {
	if hint == "" || sigName == "" {
		return 0.0
	}
	if hint == sigName {
		return 1.0
	}
	return 0.0
}

// TopMatch returns the single best match or nil if no candidates were found.
func TopMatch(input *MatchInput, db *SignatureDB) *MatchResult {
	results := MatchSignatures(input, db)
	if len(results) == 0 {
		return nil
	}
	r := results[0]
	return &r
}

// MatchByName returns all signatures whose name matches the given symbol name,
// scored against the query function. this is a fast path for ground-truth
// assisted matching (req 16.4, 16.7).
func MatchByName(input *MatchInput, db *SignatureDB, name string) []MatchResult {
	candidates := db.LookupByName(name)
	if len(candidates) == 0 {
		return []MatchResult{}
	}

	var queryFP *FunctionFingerprint
	if len(input.Instructions) > 0 {
		queryFP = ComputeFingerprint(input.Instructions, 0)
	}

	var queryCFGHash *CFGHash
	if input.FunctionCFG != nil {
		queryCFGHash = ComputeCFGHash(input.FunctionCFG)
	}

	results := make([]MatchResult, 0, len(candidates))
	for _, sig := range candidates {
		mr := scoreSig(sig, queryFP, queryCFGHash, name, defaultWeights)
		results = append(results, mr)
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].Confidence > results[j].Confidence
	})

	return results
}
