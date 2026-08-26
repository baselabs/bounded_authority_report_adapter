if Code.ensure_loaded?(Igniter) do
  defmodule Mix.Tasks.BoundedAuthorityReportAdapter.Install do
    @moduledoc """
    Scaffolds a starter key-handle module — the holder-side integration point.

        mix bounded_authority_report_adapter.install --module MyApp.HolderKey

    Everything key-shaped is deliberately UNWIRED: every callback body raises until
    you replace it with your real custody integration, so the scaffold signs nothing
    by accident — there is no road to a working key-in-process default (the same
    posture as the package's test-support reference handle, which does not ship).
    The commented sketches show the shape a real HSM/KMS/key-server wiring takes;
    see docs/getting-started.md and docs/recipes.md for the full contracts.
    """

    use Igniter.Mix.Task

    alias Igniter.Project.Formatter
    alias Igniter.Project.Module

    @shortdoc "Scaffolds a starter key-handle module"

    @impl Igniter.Mix.Task
    def info(_argv, _composing_task) do
      %Igniter.Mix.Task.Info{
        group: :bounded_authority_report_adapter,
        schema: [module: :string],
        required: [:module]
      }
    end

    @impl Igniter.Mix.Task
    def igniter(igniter) do
      module = Module.parse(igniter.args.options[:module])
      path = Module.proper_location(igniter, module)

      igniter
      |> Formatter.import_dep(:bounded_authority_report_adapter)
      |> Igniter.create_new_file(path, starter_handle_source(module))
    end

    # The starter: all five callbacks defined (so the behaviour compiles clean) but
    # every body raises — the implementations are sketches in comments. Which
    # operation needs which callback is stated inline (the moduledoc contract table
    # of BoundedAuthorityReportAdapter, as comments).
    defp starter_handle_source(module) do
      """
      defmodule #{inspect(module)} do
        @moduledoc \"\"\"
        The holder's key handle — the ONLY place this application touches key material.

        Implement each callback against your real custody store (HSM, KMS, key
        server). The adapter calls THESE functions and never sees the private key.

        Which callback matters for which operation:
          sign_report/3         -> sign/2, public_key/1, thumbprint/1
          sign_anchor/3         -> sign/2, key_identity/1 (atomic kid+pub snapshot)
          sign_grant/3          -> sign/2, signing_identity/1 (must declare :issuer)
          sign_key_transition/3 -> sign/2, key_identity/1
        \"\"\"

        @behaviour BoundedAuthorityReportAdapter

        # The handle term is whatever YOUR callbacks understand — a key reference,
        # never key bytes (see docs/security.md: the contract is the guarantee).

        @impl true
        def sign(message, _handle) when is_binary(message) do
          # Real shape (Ed25519 via your custody stack):
          #   {:ok, signature} = MyHsm.sign_ed25519(handle, message)
          #   {:ok, signature}
          raise "wire #{inspect(module)}.sign/2 to your custody store — see docs/recipes.md"
        end

        def sign(_message, _handle), do: {:error, :invalid_handle}

        @impl true
        def public_key(_handle) do
          # Real shape: {:ok, public_key} = MyHsm.public_key(handle)
          raise "wire #{inspect(module)}.public_key/1 to your custody store"
        end

        @impl true
        def thumbprint(_handle) do
          # Real shape (after public_key/1 is wired):
          #   {:ok, pub} = public_key(handle)
          #   BoundedAuthorityProtocol.V1.Jwk.public_key_thumbprint_raw(pub, %{})
          raise "wire #{inspect(module)}.thumbprint/1 (delegate to public_key/1)"
        end

        @impl true
        def key_identity(_handle) do
          # ONE atomic {key_id, public_key} snapshot — a split snapshot can sign
          # the wrong kid into an anchor header (docs/recipes.md, the KMS recipe).
          #   {:ok, {key_id, public_key}} = MyKms.current_version(handle)
          raise "wire #{inspect(module)}.key_identity/1 as ONE atomic snapshot"
        end

        @impl true
        def signing_identity(_handle) do
          # {role, key_id, public_key}; :issuer ONLY if this key really is the
          # issuer's — the C1 gate rejects non-issuer declarations, it does not
          # verify them (docs/security.md).
          #   {:ok, {:holder, key_id, public_key}} = ...
          raise "wire #{inspect(module)}.signing_identity/1"
        end
      end
      """
    end
  end
else
  defmodule Mix.Tasks.BoundedAuthorityReportAdapter.Install do
    @moduledoc """
    Install-task fallback for when the optional :igniter dependency is absent. Add
    `{:igniter, "~> 0.8", only: [:dev, :test]}` to your dev dependencies and rerun.
    """

    use Mix.Task

    @shortdoc "Scaffolds a starter key-handle module"

    @impl Mix.Task
    def run(_arguments) do
      Mix.raise("""
      bounded_authority_report_adapter.install requires the optional :igniter dependency.

      Add it to your dev dependencies and rerun:

          {:igniter, "~> 0.8", only: [:dev, :test]}

      Then: mix bounded_authority_report_adapter.install --module MyApp.HolderKey
      """)
    end
  end
end
