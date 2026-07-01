package models

type FindingTag string
type FindingStatus string

type FindingQuery struct {
	Tags     []FindingTag
	Status   FindingStatus
	MinScore int
	Search   string
}
