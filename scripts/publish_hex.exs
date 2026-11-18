# Run only from the empty upload directory, through mix run --no-mix-exs --no-start.
# This process loads Hex's client, never the project or its dependencies.
Hex.start()

auth = [key: System.fetch_env!("HEX_API_KEY")]

published! = fn label, result ->
  case result do
    {:ok, {status, _, body}} when status in 200..299 ->
      state = if is_map(body), do: body["status"], else: nil

      if status == 202 or state in ["staged", "held", "pending"] do
        IO.puts("::notice::#{label} is held for approval on Hex; publication is incomplete")
        File.write!(System.fetch_env!("GITHUB_OUTPUT"), "held=true\n", [:append])
      else
        IO.puts("#{label} upload accepted; the unkeyed read-back must still prove publication")
      end

    _ ->
      # Do not render responses: authentication failures can contain credential material.
      Mix.raise("#{label} upload failed")
  end
end

if System.fetch_env!("PUBLISH_PACKAGE") == "true" do
  result =
    Hex.API.Release.publish(
      nil,
      File.read!(System.fetch_env!("PACKAGE_ARCHIVE")),
      auth,
      fn _ -> nil end,
      replace: false
    )

  published!.("Package", result)
end

if System.fetch_env!("PUBLISH_DOCS") == "true" do
  result =
    Hex.API.ReleaseDocs.publish(
      nil,
      System.fetch_env!("PACKAGE"),
      System.fetch_env!("VERSION"),
      File.read!(System.fetch_env!("DOCS_ARCHIVE")),
      auth
    )

  published!.("Documentation", result)
end
