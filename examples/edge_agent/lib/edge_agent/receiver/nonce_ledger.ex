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
  production consumer keys a durable unique constraint to its authenticated
  identity and nonce — the point this demo makes is that the
  obligation EXISTS and is the consumer's, not the adapter's or the protocol's.

  The ETS table is a `:public` `:named_table` owned by THIS GenServer, so it lives
  as long as the receiver (started in `EdgeAgent.Receiver.start_link/1`) and is
  writable directly from the request process without a GenServer hop.
  """

  use GenServer

  @table :edge_agent_nonce_ledger
  @challenges :edge_agent_nonce_challenges

  @doc "Starts the ledger GenServer (owns both ETS tables)."
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

  @doc """
  Mints a fresh server-reserved challenge (the local-loopback profile's nonce
  reservation — the challenge is the VERIFIER's, minted here, never chosen by
  the signer). Returns the challenge value the caller signs into the proof.
  """
  @spec reserve_challenge() :: binary()
  def reserve_challenge do
    challenge = :crypto.strong_rand_bytes(18) |> Base.url_encode64(padding: false)
    true = :ets.insert_new(@challenges, {challenge, true})
    challenge
  end

  @doc """
  Atomically consumes a reserved challenge. `:ok` if `challenge` was minted by
  `reserve_challenge/0` and is unconsumed; `{:error, :unknown_challenge}`
  otherwise (never minted, or already used). `:ets.take/2` is the atomic
  take: two concurrent requests presenting the same challenge cannot both
  consume it — the first-use replay race on a no-TLS transport is what this
  closes (a captured request cannot be replayed even once, because the
  challenge it carries was consumed by the legitimate arrival).
  """
  @spec consume_challenge(binary()) :: :ok | {:error, :unknown_challenge}
  def consume_challenge(challenge) when is_binary(challenge) do
    case :ets.take(@challenges, challenge) do
      [{^challenge, true}] -> :ok
      [] -> {:error, :unknown_challenge}
    end
  end

  @impl true
  def init([]) do
    # write_concurrency (not read_concurrency): claim/2 only ever inserts_new —
    # the table is write-only in the hot path (no lookups), so the write-optimized
    # mode is the apt choice for a concurrent-request dedup ledger. The
    # challenges table additionally takes (consume_challenge/1) in the hot path.
    :ets.new(@table, [:set, :public, :named_table, write_concurrency: true])

    :ets.new(@challenges, [:set, :public, :named_table, write_concurrency: true])
    {:ok, %{}}
  end
end
