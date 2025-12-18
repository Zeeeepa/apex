import { useKeyboard } from "@opentui/react";
import { RGBA } from "@opentui/core";
import { type ModelInfo } from "../../../core/ai";
import { useAgent } from "../../agentProvider";
import { useEffect, useState } from "react";
import { AVAILABLE_MODELS } from "../../../core/ai/models";
import { useRoute } from "../../context/route";
import { useConfig } from "../../context/config";
import {
  getConfiguredProviders,
  type ProviderType,
} from "../../../core/providers";

interface GroupedModels {
  providerId: ProviderType;
  providerName: string;
  models: ModelInfo[];
  configured: boolean;
}

export default function ModelsDisplay() {
  const route = useRoute();
  const _config = useConfig();

  const [groupedModels, setGroupedModels] = useState<GroupedModels[]>([]);
  const { model: selectedModel, setModel } = useAgent();
  const [highlightedIndex, setHighlightedIndex] = useState(0);
  const [showAllForProvider, setShowAllForProvider] = useState<
    Record<string, boolean>
  >({});

  const MAX_MODELS_BEFORE_SHOW_MORE = 5;

  useEffect(() => {
    const configuredProviders = getConfiguredProviders(_config.data);

    // Group models by provider
    const grouped: GroupedModels[] = [];

    configuredProviders.forEach((provider) => {
      if (provider.configured) {
        const models = AVAILABLE_MODELS.filter(
          (m) => m.provider === provider.id
        );
        if (models.length > 0) {
          grouped.push({
            providerId: provider.id,
            providerName: provider.name,
            models,
            configured: true,
          });
        }
      }
    });

    setGroupedModels(grouped);
  }, [_config.data]);

  // Flatten the models list for navigation
  const flatModels: ModelInfo[] = [];
  groupedModels.forEach((group) => {
    const shouldShowAll = showAllForProvider[group.providerId] ?? false;
    const modelsToShow = shouldShowAll
      ? group.models
      : group.models.slice(0, MAX_MODELS_BEFORE_SHOW_MORE);
    flatModels.push(...modelsToShow);
  });

  useKeyboard((key) => {
    // Escape - Close models display
    if (key.name === "escape") {
      route.navigate({
        type: "base",
        path: "home",
      });
      return;
    }

    // Ctrl+P - Connect provider
    if (key.ctrl && key.name === "p") {
      route.navigate({
        type: "base",
        path: "providers",
      });
      return;
    }

    // Arrow Up - Previous model
    if (key.name === "up" && flatModels.length > 0) {
      setHighlightedIndex((prev) =>
        prev > 0 ? prev - 1 : flatModels.length - 1
      );
      return;
    }

    // Arrow Down - Next model
    if (key.name === "down" && flatModels.length > 0) {
      setHighlightedIndex((prev) =>
        prev < flatModels.length - 1 ? prev + 1 : 0
      );
      return;
    }

    // Enter - Select model
    if (key.name === "return" && flatModels.length > 0) {
      const sel = flatModels[highlightedIndex];
      if (sel) {
        setModel(sel);
        route.navigate({
          type: "base",
          path: "home",
        });
      }
      return;
    }
  });

  const toggleShowMore = (providerId: ProviderType) => {
    setShowAllForProvider((prev) => ({
      ...prev,
      [providerId]: !prev[providerId],
    }));
  };

  // Calculate the current flat index position
  let currentFlatIndex = 0;

  return (
    <box
      position="absolute"
      top={0}
      left={0}
      zIndex={1000}
      width="100%"
      height="100%"
      justifyContent="center"
      alignItems="center"
      backgroundColor={"transparent"}
    >
      <box
        width={70}
        maxHeight="80%"
        borderColor="green"
        backgroundColor="black"
        flexDirection="column"
        padding={2}
      >
        {/* Header */}
        <box
          flexDirection="row"
          justifyContent="space-between"
          marginBottom={2}
        >
          <text fg="green">
            Select model
          </text>
          <text fg="gray">esc</text>
        </box>

        {/* Models List */}
        <scrollbox
          style={{
            rootOptions: {
              width: "100%",
              flexGrow: 1,
              flexShrink: 1,
              overflow: "hidden",
            },
            wrapperOptions: {
              overflow: "hidden",
            },
            contentOptions: {
              flexDirection: "column",
              gap: 0,
            },
            scrollbarOptions: {
              trackOptions: {
                foregroundColor: "green",
                backgroundColor: RGBA.fromInts(40, 40, 40, 255),
              },
            },
          }}
        >
          {groupedModels.length === 0 ? (
            <box flexDirection="column" gap={1} paddingLeft={1}>
              <text fg="gray">No providers configured.</text>
              <text fg="gray">
                Press <span fg="green">Ctrl+P</span> to connect a provider.
              </text>
            </box>
          ) : (
            groupedModels.map((group) => {
              const shouldShowAll =
                showAllForProvider[group.providerId] ?? false;
              const modelsToShow = shouldShowAll
                ? group.models
                : group.models.slice(0, MAX_MODELS_BEFORE_SHOW_MORE);
              const hasMore = group.models.length > MAX_MODELS_BEFORE_SHOW_MORE;

              return (
                <box key={group.providerId} flexDirection="column" marginBottom={2}>
                  {/* Provider section header */}
                  <text fg="white" marginBottom={1}>
                    {group.providerName}
                  </text>

                  {/* Models in this provider */}
                  {modelsToShow.map((model) => {
                    const isSelected = model.id === selectedModel.id;
                    const isHighlighted =
                      flatModels[highlightedIndex]?.id === model.id;
                    currentFlatIndex++;

                    return (
                      <box
                        key={model.id}
                        flexDirection="row"
                        justifyContent="space-between"
                        paddingLeft={1}
                        paddingRight={1}
                        backgroundColor={
                          isHighlighted
                            ? RGBA.fromInts(200, 200, 0, 100)
                            : undefined
                        }
                        onMouseDown={() => {
                          setModel(model);
                          route.navigate({
                            type: "base",
                            path: "home",
                          });
                        }}
                      >
                        <text
                          fg={
                            isHighlighted ? "black" : isSelected ? "green" : "white"
                          }
                        >
                          {isHighlighted ? "● " : "  "}
                          {model.name}
                        </text>
                        {/* Show "Free" label for free models if applicable */}
                        {/* <text fg="green">Free</text> */}
                      </box>
                    );
                  })}

                  {/* Show more button */}
                  {hasMore && (
                    <box
                      paddingLeft={1}
                      onMouseDown={() => toggleShowMore(group.providerId)}
                    >
                      <text fg="gray">
                        {shouldShowAll ? "show less" : "show more"}
                      </text>
                    </box>
                  )}
                </box>
              );
            })
          )}
        </scrollbox>

        {/* Footer - Connect provider */}
        <box
          marginTop={2}
          flexDirection="column"
          gap={1}
          paddingTop={1}
        >
          <box
            flexDirection="row"
            justifyContent="space-between"
            onMouseDown={() => {
              route.navigate({
                type: "base",
                path: "providers",
              });
            }}
          >
            <text fg="green">Connect provider</text>
            <text fg="gray">ctrl+p</text>
          </box>

          {/* Help text */}
          <text fg="gray">
            <span fg="green">[↑↓]</span> Navigate ·{" "}
            <span fg="green">[ENTER]</span> Select ·{" "}
            <span fg="green">[ESC]</span> Close
          </text>
        </box>
      </box>
    </box>
  );
}
