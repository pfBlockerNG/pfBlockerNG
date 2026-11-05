package main

import (
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

func TestNameRefusalOracleChecksQuestionsNotEDNSAndRejectsExtraSections(t *testing.T) {
	for _, size := range []uint16{0, 1232} {
		query := ddrQuery(t, 17, nameFQDN, dnsmessage.TypeAAAA, size)
		reply := buildRefused(query)
		requireRefused(t, query, reply)
		q, refused := parseReply(t, query), parseReply(t, reply)
		for _, row := range []struct {
			label string
			alter func(*dnsmessage.Message)
		}{
			{"missing question", func(m *dnsmessage.Message) { m.Questions = nil }},
			{"extra question", func(m *dnsmessage.Message) { m.Questions = append(m.Questions, m.Questions[0]) }},
			{"wrong question", func(m *dnsmessage.Message) { m.Questions[0].Type = dnsmessage.TypeA }},
			{"answer", func(m *dnsmessage.Message) { m.Answers = []dnsmessage.Resource{soaRecord(q.Questions[0].Name)} }},
			{"authority", func(m *dnsmessage.Message) { m.Authorities = []dnsmessage.Resource{soaRecord(q.Questions[0].Name)} }},
			{"additional", func(m *dnsmessage.Message) { m.Additionals = []dnsmessage.Resource{soaRecord(q.Questions[0].Name)} }},
		} {
			m := refused
			m.Questions = append([]dnsmessage.Question(nil), refused.Questions...)
			row.alter(&m)
			if refusedSectionsMatch(q, m) {
				t.Errorf("EDNS size %d: refusal oracle accepted %s: %+v", size, row.label, m)
			}
		}
	}
}
