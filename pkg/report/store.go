package report

type ArtifactStore interface {
	Save(artifact ReportArtifact) error
	Get(id string) (ReportArtifact, error)
	List() ([]ReportArtifact, error)
}
