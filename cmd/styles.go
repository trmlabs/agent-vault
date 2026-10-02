package cmd

import (
	"github.com/charmbracelet/lipgloss"
	"github.com/fatih/color"
	"github.com/muesli/reflow/truncate"
)

// Color helpers — fatih/color respects NO_COLOR automatically.
var (
	colorSuccess = color.New(color.FgGreen)
	colorError   = color.New(color.FgRed)
	colorWarning = color.New(color.FgYellow)
	colorMuted   = color.New(color.FgHiBlack)
	colorBold    = color.New(color.Bold)
)

func successText(s string) string { return colorSuccess.Sprint(s) }
func errorText(s string) string   { return colorError.Sprint(s) }
func warningText(s string) string { return colorWarning.Sprint(s) }
func mutedText(s string) string   { return colorMuted.Sprint(s) }
func boldText(s string) string    { return colorBold.Sprint(s) }

// statusBadge returns a color-coded proposal status string.
func statusBadge(status string) string {
	switch status {
	case "pending":
		return colorWarning.Sprint(status)
	case "applied":
		return colorSuccess.Sprint(status)
	case "rejected":
		return colorError.Sprint(status)
	case "expired":
		return colorMuted.Sprint(status)
	default:
		return status
	}
}

// actionMarker returns a colored + or - for set/delete actions.
func actionMarker(action string) string {
	if action == "delete" {
		return colorError.Sprint("-")
	}
	return colorSuccess.Sprint("+")
}

// Lipgloss styles for structured output.
var (
	fieldLabelStyle    = lipgloss.NewStyle().Bold(true).Width(12)
	sectionHeaderStyle = lipgloss.NewStyle().Bold(true)
)

func fieldLabel(s string) string    { return fieldLabelStyle.Render(s) }
func sectionHeader(s string) string { return sectionHeaderStyle.Render(s) }
func tagText(s string) string       { return mutedText(s) }

// truncateText shortens s to width using "..." as the tail.
func truncateText(s string, width uint) string {
	return truncate.StringWithTail(s, width, "...")
}
