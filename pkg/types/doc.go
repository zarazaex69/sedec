// Package typeinfer implements type inference using Hindley-Milner unification and MaxSMT.
// It generates type constraints from IR operations, performs ASI (Aggregate Structure Identification),
// and supports interprocedural type propagation with cyclic feedback to CFG builder.
package typeinfer
