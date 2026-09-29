package custom

import "testing"

func TestPlanBindsExactValuesAndDetachesInputs(t *testing.T) {
	template := probeTemplate()
	template.Argv = []string{"probe", "--ph-name"}
	template.Env = map[string]string{"LOG_LEVEL": "info"}
	binding := validBinding()
	binding.AllowedEnvKeys = []string{"LOG_LEVEL"}
	binding.Slots = []CommandPlaceSlot{{SlotID: "name", Kind: slotString, Length: 16}}
	binding.ValueBinds = map[string]any{"name": "model-1"}
	plan, err := Plan(template, binding, posixCaps(), flavorPosix)
	if err != nil {
		t.Fatal(err)
	}
	template.Argv[0] = "changed"
	template.Env["LOG_LEVEL"] = "debug"
	binding.ValueBinds["name"] = "changed"
	if got := plan.Argv(); len(got) != 2 || got[0] != "probe" || got[1] != "model-1" {
		t.Fatalf("argv = %#v", got)
	}
	if plan.Env()["LOG_LEVEL"] != "info" {
		t.Fatalf("env = %#v", plan.Env())
	}
}

func TestPlanFailsClosedOnShellEnvironmentAndBindingDrift(t *testing.T) {
	for _, template := range []CustomActionTemplate{
		func() CustomActionTemplate { v := probeTemplate(); v.Executable = "/usr/local/bin/probe;id"; return v }(),
		func() CustomActionTemplate { v := probeTemplate(); v.Argv = []string{"probe", "$(id)"}; return v }(),
		func() CustomActionTemplate {
			v := probeTemplate()
			v.Env = map[string]string{"TOKEN": "secret"}
			return v
		}(),
	} {
		if _, err := Plan(template, validBinding(), posixCaps(), flavorPosix); err != ErrCustomPlan {
			t.Fatalf("error = %v", err)
		}
	}
	binding := validBinding()
	binding.Slots = []CommandPlaceSlot{{SlotID: "name", Kind: slotString, Length: 8}}
	binding.ValueBinds = map[string]any{"name": 7}
	template := probeTemplate()
	template.Argv = []string{"--ph-name"}
	if _, err := Plan(template, binding, posixCaps(), flavorPosix); err != ErrCustomPlan {
		t.Fatalf("error = %v", err)
	}
}

func TestPlanSupportsExplicitWindowsFlavorOnly(t *testing.T) {
	template := probeTemplate()
	template.Executable = `C:\ProgramData\LANMM\probe.exe`
	binding := validBinding()
	binding.AllowedRoots = []string{`C:\ProgramData\LANMM`}
	plan, err := Plan(template, binding, posixCaps(), flavorWin32)
	if err != nil || plan.Executable() != template.Executable {
		t.Fatalf("plan = %#v, error = %v", plan, err)
	}
	if _, err := Plan(template, binding, posixCaps(), flavorPosix); err != ErrCustomPlan {
		t.Fatalf("cross-flavor error = %v", err)
	}
}

func TestEmptyPlanEnvironmentNeverMeansInherit(t *testing.T) {
	env := toEnv(nil)
	if env == nil || len(env) != 0 {
		t.Fatalf("env = %#v; need non-nil empty environment", env)
	}
}
