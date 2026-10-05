package brokercore

// RefusalReasonField is the ErrorResponse field in which the PostgreSQL broker
// names why it refused, as a fixed reason code (the audit outcome). PostgreSQL
// never sends this field type and clients ignore unknown fields, so a relay can
// tell a broker refusal from a database server error and replace the broker's
// text with its own fixed words.
const RefusalReasonField byte = 'G'
