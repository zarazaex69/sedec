// Package cfg implements Control Flow Graph construction and analysis.
// It builds basic blocks, computes dominator trees using Lengauer-Tarjan algorithm,
// detects loops via back-edges, and supports incremental CFG updates for cyclic feedback.
package cfg
