package intelligence

import (
	"sync"
	"testing"
)

func TestInfluenceGraph_PropagationDecays(t *testing.T) {
	g := NewInfluenceGraph()
	g.AddNode("A", "phase")
	g.AddNode("B", "category")
	g.AddNode("C", "category")

	g.AddEdge("A", "B", 0.8)
	g.AddEdge("B", "C", 0.5)

	g.Propagate("A", 1.0)

	// B should receive 1.0 * 0.8 = 0.8
	influenced := g.GetInfluenced("A", 0.0)
	bWeight := nodeWeight(influenced, "B")
	cWeight := nodeWeight(influenced, "C")

	if bWeight < 0.79 || bWeight > 0.81 {
		t.Fatalf("B weight: got %f, want ~0.8", bWeight)
	}
	// C should receive 0.8 * 0.5 = 0.4
	if cWeight < 0.39 || cWeight > 0.41 {
		t.Fatalf("C weight: got %f, want ~0.4", cWeight)
	}
}

func TestInfluenceGraph_ReinforceIncreasesWeight(t *testing.T) {
	g := NewInfluenceGraph()
	g.AddNode("A", "phase")
	g.AddNode("B", "category")
	g.AddEdge("A", "B", 0.3)

	g.ReinforceEdge("A", "B", 0.2)

	// Edge weight should be 0.3 + 0.2 = 0.5
	influencers := g.TopInfluencers("B", 1)
	if len(influencers) != 1 {
		t.Fatal("expected 1 influencer")
	}
	if influencers[0].Weight < 0.49 || influencers[0].Weight > 0.51 {
		t.Fatalf("edge weight after reinforce: got %f, want ~0.5", influencers[0].Weight)
	}
}

func TestInfluenceGraph_ReinforceCapsAtOne(t *testing.T) {
	g := NewInfluenceGraph()
	g.AddNode("A", "phase")
	g.AddNode("B", "category")
	g.AddEdge("A", "B", 0.9)

	g.ReinforceEdge("A", "B", 0.5)

	influencers := g.TopInfluencers("B", 1)
	if influencers[0].Weight != 1.0 {
		t.Fatalf("edge weight should cap at 1.0, got %f", influencers[0].Weight)
	}
}

func TestInfluenceGraph_DecayDecreasesWeight(t *testing.T) {
	g := NewInfluenceGraph()
	g.AddNode("A", "phase")
	g.AddNode("B", "category")
	g.AddEdge("A", "B", 0.8)

	g.DecayEdge("A", "B", 0.5)

	influencers := g.TopInfluencers("B", 1)
	if len(influencers) != 1 {
		t.Fatal("expected 1 influencer")
	}
	if influencers[0].Weight < 0.39 || influencers[0].Weight > 0.41 {
		t.Fatalf("edge weight after decay: got %f, want ~0.4", influencers[0].Weight)
	}
}

func TestInfluenceGraph_GetInfluencedFiltersThreshold(t *testing.T) {
	g := NewInfluenceGraph()
	g.AddNode("A", "phase")
	g.AddNode("B", "category")
	g.AddNode("C", "category")

	g.AddEdge("A", "B", 0.9)
	g.AddEdge("A", "C", 0.1)

	g.Propagate("A", 1.0)

	// Only B should be above threshold 0.5
	influenced := g.GetInfluenced("A", 0.5)
	if len(influenced) != 1 {
		t.Fatalf("expected 1 node above threshold, got %d", len(influenced))
	}
	if influenced[0].ID != "B" {
		t.Fatalf("expected B, got %s", influenced[0].ID)
	}
}

func TestInfluenceGraph_TopInfluencersRanking(t *testing.T) {
	g := NewInfluenceGraph()
	g.AddNode("A", "phase")
	g.AddNode("B", "phase")
	g.AddNode("C", "phase")
	g.AddNode("target", "category")

	g.AddEdge("A", "target", 0.3)
	g.AddEdge("B", "target", 0.9)
	g.AddEdge("C", "target", 0.6)

	top := g.TopInfluencers("target", 2)
	if len(top) != 2 {
		t.Fatalf("expected 2 influencers, got %d", len(top))
	}
	if top[0].Source != "B" {
		t.Fatalf("top influencer should be B, got %s", top[0].Source)
	}
	if top[1].Source != "C" {
		t.Fatalf("second influencer should be C, got %s", top[1].Source)
	}
}

func TestInfluenceGraph_SeededCorrelationsPresent(t *testing.T) {
	g := NewInfluenceGraph()
	SeedKnownCorrelations(g)

	// Verify phase nodes exist
	if g.NodeCount() < 5 {
		t.Fatalf("expected at least 5 phase nodes, got %d total", g.NodeCount())
	}

	// Verify key correlations
	influencers := g.TopInfluencers("phase:js-analysis", 10)
	found := false
	for _, inf := range influencers {
		if inf.Source == "phase:discovery" {
			found = true
			if inf.Weight < 0.7 {
				t.Fatalf("discovery→js-analysis weight too low: %f", inf.Weight)
			}
		}
	}
	if !found {
		t.Fatal("discovery→js-analysis correlation not seeded")
	}

	// Verify params→sqli correlation
	sqliInfluencers := g.TopInfluencers("category:sqli", 10)
	found = false
	for _, inf := range sqliInfluencers {
		if inf.Source == "phase:params" {
			found = true
		}
	}
	if !found {
		t.Fatal("params→sqli correlation not seeded")
	}

	// Verify cross-category correlations
	if g.EdgeCount() < 15 {
		t.Fatalf("expected at least 15 edges, got %d", g.EdgeCount())
	}
}

func TestInfluenceGraph_PropagationDoesNotRevisit(t *testing.T) {
	g := NewInfluenceGraph()
	g.AddNode("A", "phase")
	g.AddNode("B", "phase")

	// Bidirectional edges — should not loop infinitely
	g.AddEdge("A", "B", 0.5)
	g.AddEdge("B", "A", 0.5)

	g.Propagate("A", 1.0)
	// Should complete without hanging
}

func TestInfluenceGraph_ResetWeights(t *testing.T) {
	g := NewInfluenceGraph()
	g.AddNode("A", "phase")
	g.AddNode("B", "category")
	g.AddEdge("A", "B", 0.8)

	g.Propagate("A", 1.0)

	influenced := g.GetInfluenced("A", 0.0)
	if len(influenced) == 0 || nodeWeight(influenced, "B") == 0 {
		t.Fatal("expected non-zero weight after propagation")
	}

	g.ResetWeights()

	influenced = g.GetInfluenced("A", 0.01)
	if len(influenced) != 0 {
		t.Fatalf("expected no influenced nodes after reset, got %d", len(influenced))
	}
}

func TestInfluenceGraph_ExportImport(t *testing.T) {
	g := NewInfluenceGraph()
	g.AddNode("A", "phase")
	g.AddNode("B", "category")
	g.AddEdge("A", "B", 0.7)
	g.ReinforceEdge("A", "B", 0.1) // Weight=0.8, Observations=2

	exported := g.Export()

	g2 := NewInfluenceGraph()
	g2.Import(exported)

	if g2.NodeCount() != 2 {
		t.Fatalf("expected 2 nodes, got %d", g2.NodeCount())
	}
	if g2.EdgeCount() != 1 {
		t.Fatalf("expected 1 edge, got %d", g2.EdgeCount())
	}

	influencers := g2.TopInfluencers("B", 1)
	if len(influencers) != 1 {
		t.Fatal("expected 1 influencer after import")
	}
	if influencers[0].Weight < 0.79 || influencers[0].Weight > 0.81 {
		t.Fatalf("edge weight after import: got %f, want ~0.8", influencers[0].Weight)
	}
	if influencers[0].Observations != 2 {
		t.Fatalf("observations after import: got %d, want 2", influencers[0].Observations)
	}
}

func TestInfluenceGraph_ImportNilIsNoOp(t *testing.T) {
	g := NewInfluenceGraph()
	g.Import(nil) // Should not panic
	if g.NodeCount() != 0 {
		t.Fatal("import nil should not create nodes")
	}
}

func TestInfluenceGraph_ConcurrentSafety(t *testing.T) {
	g := NewInfluenceGraph()
	g.AddNode("A", "phase")
	g.AddNode("B", "category")
	g.AddNode("C", "category")
	g.AddEdge("A", "B", 0.5)
	g.AddEdge("A", "C", 0.3)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				g.Propagate("A", 0.5)
				g.GetInfluenced("A", 0.1)
				g.TopInfluencers("B", 2)
				g.ReinforceEdge("A", "B", 0.01)
				g.DecayEdge("A", "C", 0.99)
				g.ResetWeights()
			}
		}()
	}
	wg.Wait()
}

// nodeWeight finds a node by ID in a slice and returns its weight.
func nodeWeight(nodes []InfluenceNode, id string) float64 {
	for _, n := range nodes {
		if n.ID == id {
			return n.Weight
		}
	}
	return 0
}
