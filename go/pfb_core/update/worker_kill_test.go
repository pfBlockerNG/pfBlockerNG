package update

import (
	"os"
	"strings"
	"testing"
)

func TestAHeldDescriptorCannotWriteTheNextAdmission(t *testing.T) {
	log := independentLog(t)
	held, err := os.OpenFile(log.Name(), os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer held.Close()
	resultHeld, err := os.OpenFile(log.Name()+".result", os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer resultHeld.Close()
	fresh, err := replaceRegular(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	fresh.Close()
	replaced, err := replaceRegular(log.Name() + ".result")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := replaced.WriteString("{\"version\":1,\"attempted\":[\"ipv4:new_v4\"]}\n"); err != nil {
		t.Fatal(err)
	}
	replaced.Close()
	if _, err := held.WriteString("OLDPHP\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := resultHeld.WriteString("{\"version\":1,\"outcomes\":{\"ipv4:old_v4\":\"success\"}}\n"); err != nil {
		t.Fatal(err)
	}
	body, err := os.ReadFile(log.Name())
	if err != nil {
		t.Fatal(err)
	}
	result, err := os.ReadFile(log.Name() + ".result")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), "OLDPHP") || strings.Contains(string(result), "old_v4") {
		t.Fatalf("a descriptor opened before replacement wrote the next admission: log=%q result=%q", body, result)
	}
}

func TestACompleteResultIsSalvagedOnceWhenTheWorkerDidNotPublish(t *testing.T) {
	log := independentLog(t)
	body := validWorkerJSON(t)
	if err := os.WriteFile(log.Name()+".status", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(log.Name()+".result", []byte("{\"version\":1,\"outcomes\":{\"ipv4:old_v4\":\"success\"},\"attempted\":[\"ipv4:old_v4\"]}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := Recover(log.Name(), func(_ int64, _ map[string]int64, res Result, _ error) error {
		calls++
		if res.Outcomes["ipv4:old_v4"] != "success" {
			t.Fatalf("salvaged result = %+v", res)
		}
		return nil
	})
	if err != nil || calls != 1 {
		t.Fatalf("Recover = %v, callbacks = %d; want one salvage", err, calls)
	}
	if err := Recover(log.Name(), func(int64, map[string]int64, Result, error) error {
		calls++
		return nil
	}); err != nil || calls != 1 {
		t.Fatalf("second Recover = %v, callbacks = %d; a salvaged receipt was applied again", err, calls)
	}
}

func TestSettledReceiptIsNotReapplied(t *testing.T) {
	log := independentLog(t)
	body := validWorkerJSON(t)
	body = body[:len(body)-1] + `,"finishedAt":101,"exitCode":0,"settled":true}`
	if err := os.WriteFile(log.Name()+".status", []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	calls := 0
	err := Recover(log.Name(), func(int64, map[string]int64, Result, error) error {
		calls++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatalf("settled receipt was applied %d times; receipt=%s", calls, strings.TrimSpace(body))
	}
}
