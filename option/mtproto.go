package option

// MTProtoInboundOptions configures a Telegram MTProto proxy inbound backed by
// github.com/9seconds/mtg. //H
type MTProtoInboundOptions struct {
	ListenOptions
	// Secret is the mtg proxy secret. Supports plain, dd- (secure) and ee-
	// (fake-TLS / domain fronting) forms, as parsed by mtglib.ParseSecret.
	Secret string `json:"secret"`
	// Concurrency caps the number of simultaneously served streams (0 = mtg default).
	Concurrency int `json:"concurrency,omitempty"`
}
