defmodule BoundedAuthorityReportAdapter.DocsChunk do
  @moduledoc false

  # The one reader of the EEP 48 documentation chunk that `Code.fetch_docs/1` returns.
  # Erlang/OTP owns the chunk's format tag, so this file names it and no test does.

  @type t :: %{language: atom(), module_doc: term(), entries: [tuple()]}

  @spec fetch(module()) :: {:ok, t()} | :error
  def fetch(module) do
    case Code.fetch_docs(module) do
      {:docs_v1, _anno, language, _format, module_doc, _meta, entries} ->
        {:ok, %{language: language, module_doc: module_doc, entries: entries}}

      {:error, _reason} ->
        :error
    end
  end

  @spec fetch!(module()) :: t()
  def fetch!(module) do
    case fetch(module) do
      {:ok, chunk} -> chunk
      :error -> raise ArgumentError, "#{inspect(module)} has no documentation chunk"
    end
  end
end
