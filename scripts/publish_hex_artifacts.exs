# Upload inspected archives with Hex's pinned client, without loading a Mix project.
# Usage: mix run --no-mix-exs scripts/publish_hex_artifacts.exs NAME VERSION ARCHIVE DOCS
# The unkeyed preflight selects missing uploads; the unkeyed read-back proves publication.
defmodule PublishHexArtifacts do
  @moduledoc false

  def main([name, version, archive, docs]) do
    if Mix.Project.get(), do: raise("publication must run without a Mix project")

    Hex.start()
    exists!(Hex.API.Package.get_anonymous(nil, name), name)

    # Read BOTH inspected files before either upload can begin.
    package_bytes = File.read!(archive)
    docs_bytes = File.read!(docs)
    key = System.fetch_env!("HEX_API_KEY")
    if key == "", do: raise("HEX_API_KEY is empty; publication stopped")
    auth = [key: key]

    if System.fetch_env!("PUBLISH_PACKAGE") == "true" do
      accepted!(
        Hex.API.Release.publish(nil, package_bytes, auth, fn _ -> nil end, replace: false),
        "Package"
      )
    end

    if System.fetch_env!("PUBLISH_DOCS") == "true" do
      accepted!(Hex.API.ReleaseDocs.publish(nil, name, version, docs_bytes, auth), "Documentation")
    end
  end

  def main(_argv), do: raise("usage: publish_hex_artifacts.exs NAME VERSION ARCHIVE DOCS")

  defp exists!({:ok, {200, _headers, _body}}, _name), do: :ok

  defp exists!({:ok, {404, _headers, _body}}, name) do
    raise "#{name} is not on Hex; first publication is the owner's decision"
  end

  defp exists!(_result, name) do
    raise "could not confirm #{name} exists on Hex; publication refused"
  end

  defp accepted!({:ok, {status, _headers, body}}, label) when status in 200..299 do
    state = if is_map(body), do: body["status"], else: nil

    if status == 202 or state in ["staged", "held", "pending"] do
      IO.puts("::notice::#{label} is held for approval on Hex; publication is incomplete")
      File.write!(System.fetch_env!("GITHUB_OUTPUT"), "held=true\n", [:append])
    else
      IO.puts("#{label} upload accepted; the unkeyed read-back must still prove publication")
    end
  end

  defp accepted!(_result, label) do
    # Do not render responses: authentication failures can contain credential material.
    raise "#{label} upload failed; dispatch this same commit again after resolving the failure"
  end
end

PublishHexArtifacts.main(System.argv())
