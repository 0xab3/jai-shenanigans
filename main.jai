#import "Basic";
#import "Rtp";
#import "File";
#import "Compiler";
#import "LibAV";

open_stream :: () {
  fmt_ctx := avformat_alloc_context();
  assert(fmt_ctx != null);
  filename := temp_c_string("./resources/video.h264");
  ret := avformat_open_input(*fmt_ctx, filename, null, null);
  assert(ret == 0);

  ret = avformat_find_stream_info(fmt_ctx, null);
  assert(ret == 0);

  src_video_stream: *AVStream = null;

  for 0 .. fmt_ctx.nb_streams-1 {
    stream := fmt_ctx.streams[it];
    if stream.codecpar.codec_type == AVMediaType.VIDEO src_video_stream = stream;
  }

  assert(src_video_stream != null);

  print("Stream #%: codec_type=%\n", src_video_stream.index,
            src_video_stream.codecpar.codec_id);

  read_pkt := av_packet_alloc();

  rtp_sender := rtp_sender_new("127.0.0.1", 5000);
  iter := 0;

  while av_read_frame(fmt_ctx, read_pkt) >= 0 {
    FPS :: 1/25.;

    start_time := current_time_monotonic();

    if read_pkt.stream_index == src_video_stream.index {
      as_slice: []u8 = ---;
      as_slice.data = read_pkt.data;
      as_slice.count = read_pkt.size;

      while true {
        nalu, rest, ok := extract_nalu(as_slice);
        if !ok break;
        if nalu[0]&0x1f >= 23 || nalu[0]&0x1f == 0 {
          print("nalu is %\n", nalu); assert(false);
        }
        timestamp := av_rescale_q(iter, .{1, 90000}, .{1, 25});
        iter += 1;
        write_rtp(*rtp_sender, nalu, xx timestamp);
        as_slice = rest;
      }

      end_time := current_time_monotonic();
      delta := to_milliseconds(end_time - start_time);

      sleep_milliseconds(xx (FPS * 1000  - delta));

    } else assert(false, "cowabunga");

  }
}
main :: () {
  open_stream();
}

#run {
  set_build_options_dc(.{ do_output = false });
  main();
}
