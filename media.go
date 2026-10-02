package rihma

import (
	"context"
	"errors"
	"fmt"
	"io"

	"maunium.net/go/mautrix"
	"maunium.net/go/mautrix/crypto/attachment"
	"maunium.net/go/mautrix/event"
	"maunium.net/go/mautrix/id"
)

// ErrTooLarge is returned by DownloadMedia when the media is larger than
// the limit, by declaration or in fact.
var ErrTooLarge = errors.New("rihma: media exceeds the size limit")

// DownloadMedia writes the media a message carries to w, decrypting it
// when it is encrypted, and returns the bytes written. It stops with
// ErrTooLarge once more than limit bytes arrive, so an oversized file is
// never held whole; limit <= 0 means no limit. A declared size over the
// limit fails before downloading. For encrypted media the hash is checked
// at the end: on any error, discard what w received.
func (c *Client) DownloadMedia(ctx context.Context, msg *event.MessageEventContent, limit int64, w io.Writer) (int64, error) {
	if limit > 0 && msg.Info != nil && int64(msg.Info.Size) > limit {
		return 0, fmt.Errorf("%w: declared size %d", ErrTooLarge, msg.Info.Size)
	}
	src := msg.URL
	if msg.File != nil {
		src = msg.File.URL
	}
	uri, err := src.Parse()
	if err != nil {
		return 0, fmt.Errorf("rihma: media url: %w", err)
	}
	resp, err := c.Download(ctx, uri)
	if err != nil {
		return 0, fmt.Errorf("rihma: download: %w", err)
	}
	defer resp.Body.Close()

	var body io.Reader = resp.Body
	if limit > 0 {
		// One byte past the limit tells "exactly limit" from "more".
		body = io.LimitReader(body, limit+1)
	}
	var dec io.ReadCloser
	if msg.File != nil {
		if err := msg.File.PrepareForDecryption(); err != nil {
			return 0, fmt.Errorf("rihma: encrypted media: %w", err)
		}
		dec = msg.File.DecryptStream(body)
		body = dec
	}
	n, err := io.Copy(w, body)
	if err != nil {
		return n, fmt.Errorf("rihma: download: %w", err)
	}
	if limit > 0 && n > limit {
		return n, fmt.Errorf("%w: more than %d bytes", ErrTooLarge, limit)
	}
	if dec != nil {
		if err := dec.Close(); err != nil { // checks the hash
			return n, fmt.Errorf("rihma: encrypted media: %w", err)
		}
	}
	return n, nil
}

// Media is a file to send with SendMedia.
type Media struct {
	Data     []byte
	Name     string // the file name
	MimeType string
	MsgType  event.MessageType // m.image, m.audio, m.video, or m.file
	Caption  string            // "" for none
	// RelatesTo threads or replies the message; nil for neither.
	RelatesTo *event.RelatesTo
}

// SendMedia uploads a file and sends it to room, encrypting the file
// first when the room is encrypted. With a caption it uses the Matrix
// v1.10 form: body is the caption and filename the name.
func (c *Client) SendMedia(ctx context.Context, room id.RoomID, m Media) (id.EventID, error) {
	if err := c.Connect(ctx); err != nil {
		return "", err
	}
	encrypted, err := c.StateStore.IsEncrypted(ctx, room)
	if err != nil {
		return "", fmt.Errorf("rihma: room encryption state: %w", err)
	}
	content := &event.MessageEventContent{
		MsgType: m.MsgType, Body: m.Name,
		Info:      &event.FileInfo{MimeType: m.MimeType, Size: len(m.Data)},
		RelatesTo: m.RelatesTo,
	}
	if m.Caption != "" {
		content.Body, content.FileName = m.Caption, m.Name
	}
	data, contentType := m.Data, m.MimeType
	var file *attachment.EncryptedFile
	if encrypted {
		file = attachment.NewEncryptedFile()
		data, contentType = file.Encrypt(m.Data), "application/octet-stream"
	}
	up, err := c.UploadMedia(ctx, mautrix.ReqUploadMedia{ContentBytes: data, ContentType: contentType, FileName: m.Name})
	if err != nil {
		return "", fmt.Errorf("rihma: upload: %w", err)
	}
	if file != nil {
		content.File = &event.EncryptedFileInfo{EncryptedFile: *file, URL: up.ContentURI.CUString()}
	} else {
		content.URL = up.ContentURI.CUString()
	}
	resp, err := c.SendMessageEvent(ctx, room, event.EventMessage, content)
	if err != nil {
		return "", fmt.Errorf("rihma: send: %w", err)
	}
	return resp.EventID, nil
}
