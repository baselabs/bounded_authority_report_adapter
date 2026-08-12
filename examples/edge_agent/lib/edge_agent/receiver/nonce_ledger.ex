defmodule EdgeAgent.Receiver.NonceLedger do
  @moduledoc """
  The §9 replay ledger — a CONSUMER obligation the protocol package does NOT
  perform for you.

  `BoundedAuthorityProtocol.V1.check_envelope/2` is stateless: it checks the
  proof's nonce EQUALS the expected nonce, but it does not dedupe. So a
  byte-identical captured request (same identity, valid signature, identity
  binding passes) is accepted AGAIN until `proof_max_age` expires — same-identity
  replay within the proof window. A consumer must keep a replay ledger and reject a
  seen nonce.

  This is a minimal in-memory ETS ledger keyed `(identity_thumbprint, nonce)`. A
  production consumer keys a durable unique constraint (e.g. verifier application's
  `(org_id, nonce)` on its database) — the point this demo makes is that the
  obligation EXISTS and is the consumer's, not the adapter's or the protocol's.

  The ETS table is a `:public` `:named_table` owned by THIS GenServer, so it lives
  as long as the receiver (started in `EdgeAgent.Receiver.start_link/1`) and is
  writable directly from the request process without a GenServer hop.
  """

  use GenServer

  @table :edge_agent_nonce_ledger

  @doc "Starts the ledger GenServer (owns the ETS table)."
  @spec start_link(keyword()) :: GenServer.on_start()
  def start_link(_opts \\ []), do: GenServer.start_link(__MODULE__, [], name: __MODULE__)

  @doc """
  Atomically claims `(identity_id, nonce)`. Returns `:ok` if new (the request may
  proceed), `{:error, :replay}` if already seen (a replay within the proof window
  — reject). `:ets.insert_new/2` is the atomic compare-and-insert: two concurrent
  requests for the same nonce cannot both claim it.
  """
  @spec claim(binary(), binary()) :: :ok | {:error, :replay}
  def claim(identity_id, nonce) when is_binary(identity_id) and is_binary(nonce) do
    if :ets.insert_new(@table, {{identity_id, nonce}, true}), do: :ok, else: {:error, :replay}
  end

  @impl true
  def init([]) do
    # write_concurrency (not read_concurrency): claim/2 only ever inserts_new —
    # the table is write-only in the hot path (no lookups), so the write-optimized
    # mode is the apt choice for a concurrent-request dedup ledger.
    :ets.new(@table, [:set, :public, :named_table, write_concurrency: true])
    {:ok, %{}}
  end
end
