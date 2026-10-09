# Run through mix sbom.generate (mix run --no-start). Start sbom's dependency
# applications except code-only hex_core, then its supervisor and CLI entry.
# hex_core.app lists :ssh but has no application callback; generation uses its
# functions without starting it. The upstream sbom.cyclonedx task starts the
# entire application tree, including :ssh.
output =
  case System.argv() do
    [] -> "artifacts/release.cdx.json"
    ["--output", path] -> path
    _ -> Mix.raise("usage: mix sbom.generate [--output PATH]")
  end

File.mkdir_p!(Path.dirname(output))

case Application.load(:sbom) do
  :ok -> :ok
  {:error, {:already_loaded, :sbom}} -> :ok
end

{:ok, dependencies} = :application.get_key(:sbom, :applications)

for application <- dependencies -- [:kernel, :stdlib, :elixir, :hex_core] do
  {:ok, _started} = Application.ensure_all_started(application)
end

{:ok, _supervisor} = SBoM.Application.start(:normal, [])

SBoM.CLI.run(
  [
    "cyclonedx",
    "--only",
    "prod",
    "--exclude-system-dependencies",
    "--classification",
    "library",
    "--schema",
    "1.6",
    "--format",
    "json",
    "--output",
    output,
    "--force"
  ],
  :mix
)
