import { useState, useEffect, useRef } from "react";
import { useKeyboard } from "@opentui/react";
import { exec } from "child_process";
import { existsSync } from "fs";
import { useRoute } from "../../context/route";
import { useSession } from "../../context/session";
import { useFocus } from "../../context/focus";
import { Session } from "../../../core/session";
import { Storage } from "../../../core/storage";
import { Dialog } from "../dialog";
import { Renderable, ScrollBoxRenderable } from "@opentui/core";

interface SessionsDisplayProps {
  onClose: () => void;
}

export default function SessionsDisplay({ onClose }: SessionsDisplayProps) {
  const { refocusCommandInput } = useFocus();
  const [sessions, setSessions] = useState<(Session.SessionInfo)[]>([]);
  const [selectedIndex, setSelectedIndex] = useState(0);
  const [loading, setLoading] = useState(true);
  const [statusMessage, setStatusMessage] = useState<string>("");
  const [searchTerm, setSearchTerm] = useState<string>("");

  const route = useRoute();
  const session = useSession();

  const scroll = useRef<ScrollBoxRenderable>(null);

  async function loadSessions() {
    setLoading(true);
    try {
      const _sessions = await Array.fromAsync(Session.list());
      setSessions(_sessions);
    } catch (error) {
      console.error("Error loading sessions:", error);
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadSessions();
  }, []);

  async function openReport(sessionId: string) {
    const session = await Session.get(sessionId);
    const reportPath = await Storage.locate([session.id, "pentest-report"], ".md");

    if (!existsSync(reportPath)) {
      setStatusMessage("Report not found");
      setTimeout(() => setStatusMessage(""), 2000);
      return;
    }

    exec(`open "${reportPath}"`, (error) => {
      if (error) {
        console.error("Error opening report:", error);
        setStatusMessage("Error opening report");
        setTimeout(() => setStatusMessage(""), 2000);
      } else {
        setTimeout(() => setStatusMessage(""), 2000);
      }
    });
  }


  function move(direction: number) {
    let next = selectedIndex + direction;
    console.log(next);
    if(next < 0) next = sessions.length - 1; 
    if(next >= sessions.length) next = 0;
    moveTo(next);
  }

  function moveTo(next: number) {
      if(scroll.current) {
        let target: Renderable | undefined;
        scroll.current.getChildren().find((c) => {
          let childSession = c.getChildren().find(c => c.id === sessions[next].id);
          target = childSession;
          // console.log(c.id)
          // return c.id === sessions[next].id;
      });
      if(!target) return;
      console.log(target.id)
      const y = target.y - scroll.current.y;
      if(y >= scroll.current.height) {
        scroll.current.scrollBy(y - scroll.current.height + 1);
      }
      if(y < 0) {
        scroll.current.scrollBy(y);
        if(sessions[next].id === sessions[0].id) {
          scroll.current.scrollTo(0);
        }
      }
    }
  }

  async function deleteSession(sessionId: string) {
    try {
      await Session.remove({ sessionId });
      setStatusMessage("Session deleted");
      setTimeout(() => setStatusMessage(""), 2000);

      // Reload sessions
      await loadSessions();

      // Adjust selected index if needed
      if (selectedIndex >= sessions.length && sessions.length > 0) {
        setSelectedIndex(sessions.length - 1);
      } else if (sessions.length === 0) {
        setSelectedIndex(0);
      }
    } catch (error) {
      console.error("Error deleting session:", error);
      setStatusMessage("Error deleting session");
      setTimeout(() => setStatusMessage(""), 2000);
    }
  }

  useKeyboard(async (key) => {
    // Escape - Close sessions display
    if (key.name === "escape") {
      refocusCommandInput();
      onClose();
      return;
    }

    // Enter - Activate session
    if (key.name === "return" && sessions.length > 0) {
      key.preventDefault();
      const currentSelection = sessions[selectedIndex];
      const _session = await session.load(currentSelection.id);
      console.log(_session)
      if(!_session) {
        console.error("Error loading session");
        return;
      }
      refocusCommandInput();
      onClose();
      route.navigate({
        type: "session",
        sessionId: _session.id
      });
      return;
    }

    // Arrow Up - Previous session
    if (key.name === "up" && sessions.length > 0) {
      setSelectedIndex((prev) => (prev > 0 ? prev - 1 : sessions.length - 1));
      move(-1);
      return;
    }

    // Arrow Down - Next session
    if (key.name === "down" && sessions.length > 0) {
      setSelectedIndex((prev) => (prev < sessions.length - 1 ? prev + 1 : 0));
      move(1);
      return;
    }

    // R - Open report
    if (key.name === "r" && sessions.length > 0) {
      const currentSelection = sessions[selectedIndex];
      openReport(currentSelection.id);
      return;
    }

    // Ctrl+D - Delete session
    if (key.ctrl && key.name === "d" && sessions.length > 0) {
      const currentSelection = sessions[selectedIndex];
      await deleteSession(currentSelection.id);
      return;
    }
  });

  // Filter sessions based on search term
  const filteredSessions = sessions.filter(session => {
    if (!searchTerm) return true;
    const searchLower = searchTerm.toLowerCase();
    return (
      session.id.toLowerCase().includes(searchLower)
    );
  });

  // Group sessions by date
  const groupedSessions: { date: string; sessions: (Session.SessionInfo & { index: number })[] }[] = [];
  filteredSessions.forEach((session, index) => {
    const startDate = new Date(session.time.created);
    const dateStr = startDate.toLocaleDateString('en-US', {
      weekday: 'short',
      month: 'short',
      day: 'numeric',
      year: 'numeric'
    });

    let group = groupedSessions.find(g => g.date === dateStr);
    if (!group) {
      group = { date: dateStr, sessions: [] };
      groupedSessions.push(group);
    }
    group.sessions.push({ ...session, index });
  });

  const handleClose = () => {
    refocusCommandInput();
    onClose();
  };

  return (
    <Dialog size="large" onClose={handleClose}>
      <box
        flexDirection="column"
        padding={2}
        gap={2}
        width="100%"
      >
        {/* Header */}
        <box flexDirection="row" justifyContent="space-between" width="100%">
          <text fg="white">Sessions</text>
          <text fg="gray">esc to close</text>
        </box>

        {/* Search Input */}
        <box
          width="100%"
          border={["left"]}
          borderColor="green"
          backgroundColor="transparent"
        >
          <input
            paddingLeft={1}
            backgroundColor="transparent"
            placeholder="Search sessions..."
            value={searchTerm}
            onInput={setSearchTerm}
            focused
          />
        </box>

        {/* Sessions List */}
        {loading ? (
          <text fg="gray">Loading sessions...</text>
        ) : filteredSessions.length === 0 ? (
          <text fg="gray">No sessions found</text>
        ) : (
          <box flexDirection="column" gap={2} flexGrow={1} maxHeight={5} overflow="hidden">
            <scrollbox
              ref={scroll}
              scrollbarOptions={{ visible: false }}
              style={{
                rootOptions: {
                  maxHeight: 5,
                  width: "100%",
                  flexGrow: 1,
                  flexShrink: 1,
                  overflow: "hidden",
                },
                wrapperOptions: {
                  overflow: "hidden",
                },
                contentOptions: {
                  gap: 2,
                  flexDirection: "column",
                },
              }}
            >
              {groupedSessions.map((group) => (
                <box key={group.date} flexDirection="column" gap={1}>
                  {/* Date Header */}
                  <text fg="green">{group.date}</text>

                  {/* Sessions in this date group */}
                  {group.sessions.map((session) => {
                    const isSelected = session.index === selectedIndex;
                    const startTime = new Date(session.time.created);
                    const timeStr = startTime.toLocaleTimeString('en-US', {
                      hour: 'numeric',
                      minute: '2-digit',
                      hour12: true
                    });

                    return (
                      <box
                        id={session.id}
                        key={session.id}
                        onMouseDown={() => setSelectedIndex(session.index)}
                        backgroundColor="transparent"
                        border={isSelected ? ["left"] : undefined}
                        borderColor={isSelected ? "green" : undefined}
                        paddingLeft={2}
                        flexDirection="row"
                        justifyContent="space-between"
                        width="100%"
                      >
                        <text fg={isSelected ? "white" : "gray"}>
                          {isSelected ? "● " : "  "}{session.name}
                        </text>
                        <text fg="gray">{timeStr}</text>
                      </box>
                    );
                  })}
                </box>
              ))}
            </scrollbox>
          </box>
        )}

        {/* Actions Footer */}
        {filteredSessions.length > 0 && (
          <box flexDirection="row" gap={2}>
            <text fg="gray">
              <span fg="green">[Enter]</span> Open · <span fg="green">[R]</span> Report · <span fg="green">[Ctrl+D]</span> Delete
            </text>
          </box>
        )}

        {statusMessage && (
          <text fg="green">{statusMessage}</text>
        )}
      </box>
    </Dialog>
  );
}